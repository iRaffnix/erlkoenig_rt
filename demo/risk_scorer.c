/*
 * risk_scorer.c — Transaction risk scoring worker.
 *
 * Runs inside an erlkoenig container. Connects to PostgreSQL,
 * reads customer profile, computes risk score for a transaction.
 *
 * Usage:  /app <customer_id> <amount> <country>
 * Output: JSON risk assessment on stdout
 *
 * PostgreSQL connection via raw wire protocol (no libpq dependency).
 * Static musl binary, ~30 KB.
 *
 * Build: musl-gcc -static -O2 -o risk_scorer risk_scorer.c
 */

#include <arpa/inet.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <unistd.h>

/* --- PostgreSQL wire protocol (minimal) --- */

/*
 * PG wire protocol v3:
 * - StartupMessage: length(4) + version(4) + "user\0val\0database\0val\0\0"
 * - Query: 'Q' + length(4) + sql\0
 * - Response: 'T' (RowDescription) + 'D' (DataRow) + 'C' (CommandComplete) + 'Z' (ReadyForQuery)
 * - AuthOk: 'R' + length(4) + status(4)=0
 */

static int pg_connect(const char *host, int port, const char *user,
		      const char *pass, const char *dbname)
{
	int fd = socket(AF_INET, SOCK_STREAM, 0);

	if (fd < 0)
		return -1;

	struct sockaddr_in addr = {
		.sin_family = AF_INET,
		.sin_port = htons((uint16_t)port),
	};
	inet_pton(AF_INET, host, &addr.sin_addr);

	if (connect(fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
		close(fd);
		return -1;
	}

	/* StartupMessage: version 3.0 + params */
	char buf[512];
	int pos = 4; /* skip length, fill later */
	uint32_t version = htonl(0x00030000); /* 3.0 */

	memcpy(buf + pos, &version, 4);
	pos += 4;

	/* user */
	memcpy(buf + pos, "user", 5);
	pos += 5;
	int ulen = (int)strlen(user);
	memcpy(buf + pos, user, (size_t)(ulen + 1));
	pos += ulen + 1;

	/* database */
	memcpy(buf + pos, "database", 9);
	pos += 9;
	int dlen = (int)strlen(dbname);
	memcpy(buf + pos, dbname, (size_t)(dlen + 1));
	pos += dlen + 1;

	/* terminator */
	buf[pos++] = '\0';

	/* fill length */
	uint32_t len = htonl((uint32_t)pos);

	memcpy(buf, &len, 4);
	write(fd, buf, (size_t)pos);

	/* Read AuthOk (or AuthCleartextPassword) */
	char resp[1024];
	ssize_t n = read(fd, resp, sizeof(resp));

	if (n < 9)
		goto fail;

	if (resp[0] == 'R') {
		uint32_t auth_type;

		memcpy(&auth_type, resp + 5, 4);
		auth_type = ntohl(auth_type);

		if (auth_type == 3) {
			/* CleartextPassword: send password */
			int plen = (int)strlen(pass);
			char pbuf[256];

			pbuf[0] = 'p';
			uint32_t pmsglen = htonl((uint32_t)(4 + plen + 1));

			memcpy(pbuf + 1, &pmsglen, 4);
			memcpy(pbuf + 5, pass, (size_t)(plen + 1));
			write(fd, pbuf, (size_t)(5 + plen + 1));

			/* Read auth response */
			n = read(fd, resp, sizeof(resp));
			if (n < 5)
				goto fail;
		} else if (auth_type == 0) {
			/* AuthOk — may have more messages after */
		} else {
			/* md5 or other — not supported */
			goto fail;
		}
	}

	/* Drain until ReadyForQuery ('Z') */
	for (int tries = 0; tries < 10; tries++) {
		for (ssize_t i = 0; i < n; i++) {
			if (resp[i] == 'Z')
				return fd;
		}
		n = read(fd, resp, sizeof(resp));
		if (n <= 0)
			break;
	}

	return fd; /* hope for the best */

fail:
	close(fd);
	return -1;
}

static int pg_query(int fd, const char *sql, char *result, size_t result_sz)
{
	/* Send Query message */
	int slen = (int)strlen(sql);
	char buf[4096];

	buf[0] = 'Q';
	uint32_t msglen = htonl((uint32_t)(4 + slen + 1));

	memcpy(buf + 1, &msglen, 4);
	memcpy(buf + 5, sql, (size_t)(slen + 1));
	write(fd, buf, (size_t)(5 + slen + 1));

	/* Read response — extract first DataRow values */
	char resp[8192];
	ssize_t n = read(fd, resp, sizeof(resp));

	if (n <= 0)
		return -1;

	/* Scan for 'D' (DataRow) message */
	result[0] = '\0';
	size_t rpos = 0;

	for (ssize_t i = 0; i < n;) {
		char mtype = resp[i];

		if (i + 5 > n)
			break;

		uint32_t mlen;

		memcpy(&mlen, resp + i + 1, 4);
		mlen = ntohl(mlen);

		if (mtype == 'D' && i + 1 + (ssize_t)mlen <= n) {
			/* DataRow: field_count(2) + fields */
			int fpos = (int)i + 5;
			uint16_t ncols;

			memcpy(&ncols, resp + fpos, 2);
			ncols = ntohs(ncols);
			fpos += 2;

			for (int c = 0; c < ncols && fpos + 4 <= (int)n; c++) {
				int32_t flen;

				memcpy(&flen, resp + fpos, 4);
				flen = (int32_t)ntohl((uint32_t)flen);
				fpos += 4;

				if (flen > 0 && fpos + flen <= (int)n) {
					if (rpos > 0 && rpos < result_sz - 1)
						result[rpos++] = '\t';
					size_t copy = (size_t)flen;

					if (rpos + copy >= result_sz - 1)
						copy = result_sz - rpos - 1;
					memcpy(result + rpos, resp + fpos, copy);
					rpos += copy;
					fpos += flen;
				} else if (flen == -1) {
					/* NULL */
					if (rpos > 0 && rpos < result_sz - 1)
						result[rpos++] = '\t';
					fpos += 0;
				}
			}
		}

		i += 1 + (ssize_t)mlen;
	}

	result[rpos] = '\0';
	return rpos > 0 ? 0 : -1;
}

/* --- Risk scoring logic --- */

static double compute_risk(double amount, double avg_amount,
			   double max_amount, const char *tx_country,
			   const char *cust_country, const char *risk_tier)
{
	double score = 0.0;

	/* Amount deviation from average */
	if (avg_amount > 0) {
		double deviation = amount / avg_amount;

		if (deviation > 3.0)
			score += 40.0;
		else if (deviation > 2.0)
			score += 20.0;
		else if (deviation > 1.5)
			score += 10.0;
	}

	/* Exceeds historical maximum */
	if (amount > max_amount)
		score += 25.0;

	/* Country mismatch */
	if (strcmp(tx_country, cust_country) != 0)
		score += 15.0;

	/* High-risk countries */
	if (strcmp(tx_country, "RU") == 0 || strcmp(tx_country, "NG") == 0 ||
	    strcmp(tx_country, "CN") == 0)
		score += 20.0;

	/* Customer risk tier */
	if (strcmp(risk_tier, "high") == 0)
		score += 15.0;
	else if (strcmp(risk_tier, "low") == 0)
		score -= 10.0;

	/* Clamp */
	if (score < 0.0)
		score = 0.0;
	if (score > 100.0)
		score = 100.0;

	return score;
}

int main(int argc, char **argv)
{
	if (argc < 4) {
		fprintf(stderr,
			"Usage: %s <customer_id> <amount> <country>\n",
			argv[0]);
		return 1;
	}

	int customer_id = atoi(argv[1]);
	double amount = atof(argv[2]);
	const char *tx_country = argv[3];

	/* Connect to PostgreSQL (host gateway is 10.0.0.1 from container) */
	const char *pg_host = getenv("PG_HOST");

	if (!pg_host)
		pg_host = "10.0.0.1";

	int db = pg_connect(pg_host, 5432, "ek", "ek", "erlkoenig");

	if (db < 0) {
		printf("{\"error\":\"db_connect_failed\"}\n");
		return 1;
	}

	/* Query customer profile */
	char sql[256];

	snprintf(sql, sizeof(sql),
		 "SELECT name, country, avg_amount, max_amount, risk_tier "
		 "FROM customers WHERE id = %d",
		 customer_id);

	char result[1024];

	if (pg_query(db, sql, result, sizeof(result)) < 0) {
		printf("{\"error\":\"customer_not_found\",\"id\":%d}\n",
		       customer_id);
		close(db);
		return 1;
	}

	/* Parse tab-separated: name\tcountry\tavg\tmax\ttier */
	char cust_name[128] = "", cust_country[8] = "", tier[16] = "";
	double avg_amount = 0, max_amount = 0;
	char *fields[5];
	int nf = 0;
	char *p = result;

	for (int i = 0; i < 5 && p; i++) {
		fields[i] = p;
		p = strchr(p, '\t');
		if (p)
			*p++ = '\0';
		nf++;
	}

	if (nf >= 5) {
		strncpy(cust_name, fields[0], sizeof(cust_name) - 1);
		strncpy(cust_country, fields[1], sizeof(cust_country) - 1);
		avg_amount = atof(fields[2]);
		max_amount = atof(fields[3]);
		strncpy(tier, fields[4], sizeof(tier) - 1);
	}

	close(db);

	/* Compute risk score */
	double score =
		compute_risk(amount, avg_amount, max_amount, tx_country,
			     cust_country, tier);

	const char *verdict = "approve";

	if (score >= 70.0)
		verdict = "reject";
	else if (score >= 40.0)
		verdict = "review";

	/* Output JSON */
	printf("{\"customer\":\"%s\",\"customer_id\":%d,"
	       "\"tx_amount\":%.2f,\"tx_country\":\"%s\","
	       "\"avg_amount\":%.2f,\"max_amount\":%.2f,"
	       "\"risk_score\":%.1f,\"verdict\":\"%s\"}\n",
	       cust_name, customer_id, amount, tx_country, avg_amount,
	       max_amount, score, verdict);

	return 0;
}
