//wget https://openssl-library.org/source/
//tar xzvf ... && cd ... && ./config && make
//gcc -I $(pwd)/openssl-*/include ./openssl-*/libcrypto.a -Wall ecdh.c -o /tmp/exe

#include <openssl/obj_mac.h>
#include <openssl/bn.h>
#include <openssl/ec.h>
#include <openssl/evp.h>

#include <ctype.h>
#include <fcntl.h>
#include <stdio.h>
#include <time.h>
#include <unistd.h>

typedef unsigned char uchar;

void rnds(unsigned char *b, int l)
{
	int f = open("/dev/urandom", O_RDONLY);
	int r = read(f, b, l);
	if (r < 1) { /* no-op */ }
	close(f);
}

uchar *hash(char *ixno, char *iyno)
{
	char *lets = "0123456789abcdef";
	char outh[EVP_MAX_MD_SIZE*4];
	unsigned int hlen = 0;
	unsigned char data[EVP_MAX_MD_SIZE];
	EVP_MD_CTX *ctxh = EVP_MD_CTX_new();

	EVP_DigestInit_ex(ctxh, EVP_sha256(), NULL);
	EVP_DigestUpdate(ctxh, ixno, strlen(ixno));
	EVP_DigestUpdate(ctxh, iyno, strlen(iyno));
	EVP_DigestFinal_ex(ctxh, data, &hlen);
	EVP_MD_CTX_free(ctxh);

	bzero(outh, EVP_MAX_MD_SIZE*4);
	for (int x = 0; x < 32; ++x)
	{
		outh[(x*2)+0] = lets[(data[x] >> 4) & 0xf];
		outh[(x*2)+1] = lets[(data[x] >> 0) & 0xf];
	}

	return (uchar *)strdup(outh);
}

int EC_POINT_sub(const EC_GROUP *g, EC_POINT *r, const EC_POINT *p, const EC_POINT *q, BN_CTX *ctx)
{
	int good = 0;
	EC_POINT *n = EC_POINT_new(g);
	if (n == NULL) { return 0; }
	if (!EC_POINT_copy(n, q)) { goto erro; }
	if (!EC_POINT_invert(g, n, ctx)) { goto erro; }
	if (!EC_POINT_add(g, r, p, n, ctx)) { goto erro; }
	good = 1;

erro:

	EC_POINT_free(n);
	return good;
}

uchar *pnum(char *pstr, BIGNUM *bnum)
{
	char *a = BN_bn2hex(bnum);
	if (pstr != NULL) { printf("%s: [%s]\n", pstr, a); }
	return (uchar *)a;
}

void ppnt(char *pstr, EC_POINT *ecpt, EC_GROUP *ecgr, BN_CTX *bctx)
{
	BIGNUM *x = BN_new();
	BIGNUM *y = BN_new();
	EC_POINT_get_affine_coordinates(ecgr, ecpt, x, y, bctx);
	char *a = BN_bn2hex(x);
	char *b = BN_bn2hex(y);
	if (pstr != NULL) { printf("%s: (%s, %s)\n", pstr, a, b); }
	OPENSSL_free(a);
	OPENSSL_free(b);
	BN_free(x);
	BN_free(y);
}

void egen(uchar **sk, uchar **sx, uchar **sy, uchar **ck, uchar **cx, uchar **cy, EC_GROUP *ecgr, BN_CTX *bctx)
{
	unsigned char sint[32];
	rnds(sint, 32);
	BIGNUM *skno = BN_bin2bn(sint, 32, NULL);
	EC_POINT *spnt = EC_POINT_new(ecgr);
	EC_POINT_mul(ecgr, spnt, skno, NULL, NULL, bctx);
	BIGNUM *cxno = BN_new(), *cyno = BN_new();
	EC_POINT_get_affine_coordinates(ecgr, spnt, cxno, cyno, bctx);

	unsigned char cint[32];
	rnds(cint, 32);
	BIGNUM *ckno = BN_bin2bn(cint, 32, NULL);
	EC_POINT *cpnt = EC_POINT_new(ecgr);
	EC_POINT_mul(ecgr, cpnt, ckno, NULL, NULL, bctx);
	BIGNUM *sxno = BN_new(), *syno = BN_new();
	EC_POINT_get_affine_coordinates(ecgr, cpnt, sxno, syno, bctx);

	printf("\n");

	printf("server\n");
	*sk = pnum("sk", skno);
	*sx = pnum("sx", sxno);
	*sy = pnum("sy", syno);

	printf("\n");

	printf("client\n");
	*ck = pnum("ck", ckno);
	*cx = pnum("cx", cxno);
	*cy = pnum("cy", cyno);
	printf("\n");

	BN_free(skno); BN_free(sxno); BN_free(syno);
	BN_free(ckno); BN_free(cxno); BN_free(cyno);
	EC_POINT_free(spnt); EC_POINT_free(cpnt);
}

void ekpe(uchar **mk, uchar **cx, uchar **cy, uchar **ex, uchar **ey, uchar **mh, char *pstr, uchar *kx, uchar *ky, EC_GROUP *ecgr, BN_CTX *bctx)
{
	BIGNUM *xpnt = NULL, *ypnt = NULL;
	BN_hex2bn(&xpnt, (char *)kx);
	BN_hex2bn(&ypnt, (char *)ky);
	EC_POINT *qpnt = EC_POINT_new(ecgr);
	EC_POINT_set_affine_coordinates(ecgr, qpnt, xpnt, ypnt, bctx);

	unsigned char mint[32];
	rnds(mint, 32);
	BIGNUM *mnum = BN_bin2bn(mint, 32, NULL);
	EC_POINT *mpnt = EC_POINT_new(ecgr);
	EC_POINT_mul(ecgr, mpnt, mnum, NULL, NULL, bctx);

	unsigned char rint[32];
	rnds(rint, 32);
	BIGNUM *rnum = BN_bin2bn(rint, 32, NULL);
	EC_POINT *cpnt = EC_POINT_new(ecgr);
	EC_POINT_mul(ecgr, cpnt, rnum, NULL, NULL, bctx);

	EC_POINT *epnt = EC_POINT_new(ecgr);
	EC_POINT_mul(ecgr, epnt, NULL, qpnt, rnum, bctx);
	EC_POINT_add(ecgr, epnt, epnt, mpnt, bctx);

	uchar *mx = NULL, *my = NULL;
	BIGNUM *mxno = BN_new(), *myno = BN_new();
	EC_POINT_get_affine_coordinates(ecgr, mpnt, mxno, myno, bctx);
	mx = pnum(NULL, mxno);
	my = pnum(NULL, myno);
	*mh = hash((char *)mx, (char *)my);

	printf("%s\n", pstr);
	uchar *rn = NULL;
	ppnt("M", mpnt, ecgr, bctx);
	*mk = pnum("m", mnum);
	rn = pnum("r", rnum);
	printf("publish\n");
	ppnt("C", cpnt, ecgr, bctx);
	ppnt("E", epnt, ecgr, bctx);
	printf("H: {%s}\n", (char *)*mh);
	printf("\n");

	BIGNUM *exno = BN_new(), *eyno = BN_new();
	EC_POINT_get_affine_coordinates(ecgr, epnt, exno, eyno, bctx);
	*ex = pnum(NULL, exno);
	*ey = pnum(NULL, eyno);

	BIGNUM *cxno = BN_new(), *cyno = BN_new();
	EC_POINT_get_affine_coordinates(ecgr, cpnt, cxno, cyno, bctx);
	*cx = pnum(NULL, cxno);
	*cy = pnum(NULL, cyno);

	OPENSSL_free(rn); OPENSSL_free(mx); OPENSSL_free(my);
	BN_free(mxno); BN_free(myno);
	BN_free(exno); BN_free(eyno); BN_free(cxno); BN_free(cyno);
	BN_free(xpnt); BN_free(ypnt); BN_free(mnum); BN_free(rnum);
	EC_POINT_free(cpnt); EC_POINT_free(epnt); EC_POINT_free(qpnt); EC_POINT_free(mpnt);
}

void ekpd(uchar **mk, uchar **sx, uchar **sy, char *pstr, uchar *cx, uchar *cy, uchar *ex, uchar *ey, uchar *mh, uchar *kn, EC_GROUP *ecgr, BN_CTX *bctx)
{
	BIGNUM *cxno = NULL, *cyno = NULL;
	BN_hex2bn(&cxno, (char *)cx);
	BN_hex2bn(&cyno, (char *)cy);
	EC_POINT *cpnt = EC_POINT_new(ecgr);
	EC_POINT_set_affine_coordinates(ecgr, cpnt, cxno, cyno, bctx);

	BIGNUM *exno = NULL, *eyno = NULL;
	BN_hex2bn(&exno, (char *)ex);
	BN_hex2bn(&eyno, (char *)ey);
	EC_POINT *epnt = EC_POINT_new(ecgr);
	EC_POINT_set_affine_coordinates(ecgr, epnt, exno, eyno, bctx);

	BIGNUM *knum = NULL;
	BN_hex2bn(&knum, (char *)kn);
	EC_POINT *dpnt = EC_POINT_new(ecgr);
	EC_POINT_mul(ecgr, dpnt, NULL, cpnt, knum, bctx);

	EC_POINT *mpnt = EC_POINT_new(ecgr);
	EC_POINT_sub(ecgr, mpnt, epnt, dpnt, bctx);

	BIGNUM *mkno = NULL;
	BN_hex2bn(&mkno, (char *)*mk);
	EC_POINT *spnt = EC_POINT_new(ecgr);
	EC_POINT_mul(ecgr, spnt, NULL, mpnt, mkno, bctx);

	uchar *hh = NULL;
	uchar *mx = NULL, *my = NULL;
	BIGNUM *mxno = BN_new(), *myno = BN_new();
	EC_POINT_get_affine_coordinates(ecgr, mpnt, mxno, myno, bctx);
	mx = pnum(NULL, mxno);
	my = pnum(NULL, myno);
	hh = hash((char *)mx, (char *)my);

	printf("%s\n", pstr);
	uchar *mn = NULL;
	ppnt("M", mpnt, ecgr, bctx);
	mn = pnum("m", mkno);
	printf("H: {%s}\n", (char *)hh);
	ppnt("D", dpnt, ecgr, bctx);
	ppnt("S", spnt, ecgr, bctx);
	printf("\n");

	BIGNUM *sxno = BN_new(), *syno = BN_new();
	EC_POINT_get_affine_coordinates(ecgr, spnt, sxno, syno, bctx);
	if ((strlen((char *)mh) != 64) || (strlen((char *)hh) != strlen((char *)mh)) || (strncmp((char *)hh, (char *)mh, 64) != 0))
	{
		printf("!: [%s] != [%s]\n", mh, hh);
		*sx = NULL; *sy = NULL;
	}
	else
	{
		*sx = pnum(NULL, sxno); *sy = pnum(NULL, syno);
	}

	OPENSSL_free(mn); OPENSSL_free(mx); OPENSSL_free(my); OPENSSL_free(hh);
	BN_free(mxno); BN_free(myno);
	BN_free(cxno); BN_free(cyno); BN_free(exno); BN_free(eyno);
	BN_free(sxno); BN_free(syno); BN_free(mkno); BN_free(knum);
	EC_POINT_free(cpnt); EC_POINT_free(epnt); EC_POINT_free(dpnt); EC_POINT_free(mpnt); EC_POINT_free(spnt);
}

int main(int argc, char **argv)
{
	BN_CTX *bctx = BN_CTX_new();
	EC_GROUP *ecgr = EC_GROUP_new_by_curve_name(NID_X9_62_prime256v1);

	uchar *ck, *cx, *cy;
	uchar *cmkn, *csxn, *csyn;

	uchar *sk, *sx, *sy;
	uchar *smkn, *ssxn, *ssyn;

	uchar *ccxn, *ccyn, *cexn, *ceyn, *chsh;
	uchar *scxn, *scyn, *sexn, *seyn, *shsh;

	egen(&sk, &sx, &sy, &ck, &cx, &cy, ecgr, bctx);

	printf("\n\n");

	ekpe(&cmkn, &ccxn, &ccyn, &cexn, &ceyn, &chsh, "c->s", cx, cy, ecgr, bctx);

	ekpe(&smkn, &scxn, &scyn, &sexn, &seyn, &shsh, "s->c", sx, sy, ecgr, bctx);

	printf("\n\n");

	ekpd(&smkn, &ssxn, &ssyn, "s<-c", ccxn, ccyn, cexn, ceyn, chsh, sk, ecgr, bctx);

	ekpd(&cmkn, &csxn, &csyn, "c<-s", scxn, scyn, sexn, seyn, shsh, ck, ecgr, bctx);

	OPENSSL_free(cmkn); OPENSSL_free(csxn); OPENSSL_free(csyn);
	OPENSSL_free(ck); OPENSSL_free(cx); OPENSSL_free(cy);

	OPENSSL_free(smkn); OPENSSL_free(ssxn); OPENSSL_free(ssyn);
	OPENSSL_free(sk); OPENSSL_free(sx); OPENSSL_free(sy);

	OPENSSL_free(ccxn); OPENSSL_free(ccyn); OPENSSL_free(cexn); OPENSSL_free(ceyn); OPENSSL_free(chsh);
	OPENSSL_free(scxn); OPENSSL_free(scyn); OPENSSL_free(sexn); OPENSSL_free(seyn); OPENSSL_free(shsh);

	BN_CTX_free(bctx);
	EC_GROUP_free(ecgr);

	return 0;
}
