//./config && make
//cp -frv ./openssl-*/include/openssl /usr/local/include/
//cp -frv ./openssl-*/libcrypto*dylib /usr/local/lib/
//rm /tmp/exe ; gcc -Wno-deprecated -Wall -lcrypto -o /tmp/exe eckx.c
//openssl ecparam -name secp256k1 -genkey -noout -out /tmp/skey.pem
//openssl ec -in /tmp/skey.pem -pubout -out /tmp/ckey.pem

#include <openssl/bio.h>
#include <openssl/pem.h>
#include <openssl/bn.h>
#include <openssl/ec.h>
#include <openssl/err.h>
#include <ctype.h>
#include <stdio.h>
#include <time.h>

EC_KEY *pkey(char *path, int kind) {
	EC_KEY *keyo = NULL;
	EVP_PKEY *evpo = EVP_PKEY_new();
	BIO *bioo = BIO_new_file(path, "r");

	if (kind == 0) {
		PEM_read_bio_PrivateKey(bioo, &evpo, NULL, NULL);
		keyo = EVP_PKEY_get1_EC_KEY(evpo);
	} else {
		PEM_read_bio_PUBKEY(bioo, &evpo, NULL, NULL);
		keyo = EVP_PKEY_get1_EC_KEY(evpo);
	}

	BIO_free_all(bioo);
	EVP_PKEY_free(evpo);
	return keyo;
}

char **pmul(EC_KEY *keyo, char *inpt, EC_POINT *ecxy) {
	const EC_GROUP *ecgr = EC_KEY_get0_group(keyo);

	int news = 0;
	char **outp = malloc(2 * sizeof(char *));
	BIGNUM *xval = BN_new();
	BIGNUM *yval = BN_new();

	EC_POINT *ecor = EC_POINT_new(ecgr);
	if (ecxy == NULL) {
		news = 1;
		ecxy = EC_POINT_new(ecgr);
		EC_POINT_copy(ecxy, EC_GROUP_get0_generator(ecgr));
	}

	BIGNUM *numb = BN_new();
	BN_CTX *mult = BN_CTX_new();

	BN_hex2bn(&numb, inpt);
	EC_POINT_mul(ecgr, ecor, NULL, ecxy, numb, mult);

	EC_POINT_get_affine_coordinates_GFp(ecgr, ecor, xval, yval, mult);
	outp[0] = BN_bn2hex(xval);
	outp[1] = BN_bn2hex(yval);

	BN_free(numb);
	BN_free(xval);
	BN_free(yval);
	BN_CTX_free(mult);
	EC_POINT_free(ecor);
	if (news == 1) { EC_POINT_free(ecxy); }
	return outp;
}

EC_POINT *xpyp(EC_KEY *keyo, char *xstr, char *ystr) {
	const EC_GROUP *ecgr = EC_KEY_get0_group(keyo);

	BIGNUM *xnum = BN_new();
	BIGNUM *ynum = BN_new();

	BN_hex2bn(&xnum, xstr);
	BN_hex2bn(&ynum, ystr);

	EC_POINT *outp = EC_POINT_new(ecgr);
	BN_CTX *ctxo = BN_CTX_new();

	EC_POINT_set_affine_coordinates(ecgr, outp, xnum, ynum, ctxo);

	BN_free(xnum);
	BN_free(ynum);
	BN_CTX_free(ctxo);
	return outp;
}

void rnds(char *outp, int bits, int size) {
	char *hexl = "0123456789abcdef";
	bzero(outp, size);
	for (int x = 0; x < (bits / 4); ++x) {
		outp[x] = hexl[rand() & 0xf];
	}
}

int hexv(char inpt) {
	inpt = tolower(inpt);
	if (('0' <= inpt) && (inpt <= '9')) {
		return (inpt - '0');
	}
	if (('a' <= inpt) && (inpt <= 'f')) {
		return (inpt - 'a');
	}
	return 0;
}

char **sign(EC_KEY *pubk, unsigned char *data, int size, EC_POINT *ecxy) {
	const EC_POINT *pubp = ecxy;
	if (ecxy == NULL) {
		pubp = EC_KEY_get0_public_key(pubk);
	}

	int leng = (size * 4);
	char inpt[leng], rstr[384];
	char *hexl = "0123456789abcdef";
	char **ptsr, **ptsp;
	char **outp = malloc(4 * sizeof(char *));

	bzero(inpt, leng);
	for (int x = 0, y = 0; x < size; ++x, y += 2) {
		//inpt[y] = hexl[(data[x] >> 4) & 0xf];
		//inpt[y + 1] = hexl[data[x] & 0xf];
		inpt[x] = data[x];
	}
	rnds(rstr, 96, 384);

	ptsr = pmul(pubk, rstr, NULL);
	ptsp = pmul(pubk, rstr, (EC_POINT *)pubp);

	BIGNUM *xnum = BN_new();
	BIGNUM *ynum = BN_new();
	BIGNUM *dnum = BN_new();
	BIGNUM *rnum = BN_new();
	BIGNUM *snum = BN_new();

	BN_hex2bn(&xnum, ptsp[0]);
	BN_hex2bn(&ynum, ptsp[1]);
	BN_hex2bn(&dnum, inpt);

	BN_add(snum, xnum, ynum);
	BN_add(rnum, snum, dnum);

	outp[0] = ptsr[0];
	outp[1] = ptsr[1];
	outp[2] = BN_bn2hex(rnum);
	outp[3] = NULL;//rstr

	BN_free(xnum);
	BN_free(ynum);
	BN_free(dnum);
	BN_free(rnum);
	BN_free(snum);
	free(ptsp[1]); free(ptsp[0]);
	free(ptsr); free(ptsp);
	return outp;
}

char *vrfy(EC_KEY *prik, char *xstr, char *ystr, char *sstr, BIGNUM *priz) {
	const BIGNUM *prip = priz;
	if (priz == NULL) {
		prip = EC_KEY_get0_private_key(prik);
	}

	int slen, leng = (strlen(sstr) + 9);
	char *temp = NULL, *data = malloc(leng);
	char *pris = BN_bn2hex(prip);
	EC_POINT *pntr = xpyp(prik, xstr, ystr);
	char **pnts = pmul(prik, pris, pntr);

	BIGNUM *xnum = BN_new();
	BIGNUM *ynum = BN_new();
	BIGNUM *snum = BN_new();
	BIGNUM *rnum = BN_new();
	BIGNUM *dnum = BN_new();

	BN_hex2bn(&xnum, pnts[0]);
	BN_hex2bn(&ynum, pnts[1]);
	BN_hex2bn(&snum, sstr);

	BN_sub(rnum, snum, ynum);
	BN_sub(dnum, rnum, xnum);

	temp = BN_bn2hex(dnum);
	slen = strlen(temp);
	bzero(data, leng);
	for (int x = 0, y = 0; (x < (leng - 3)) && (y < slen); ++x, ++y) {
		//data[x / 2] = ((data[x / 2] << 4) + hexv(temp[y]));
		data[y] = temp[y];
	}

	free(pris); free(temp);
	free(pnts[1]); free(pnts[0]); free(pnts);
	BN_free(xnum);
	BN_free(ynum);
	BN_free(snum);
	BN_free(rnum);
	BN_free(dnum);
	EC_POINT_free(pntr);
	return data;
}

int main() {
	char *asig, *bsig, *csig, *dsig, *zsig;
	char **ptsa, **ptsb, **ptsc, **ptsd, **ptsz;
	char **siga, **sigb, **sigc, **sigd, **sigz;
	char sstr[384], cstr[384], zstr[384];
	BIGNUM *znum = BN_new();
	EC_POINT *spnt, *cpnt, *zpnt;
	EC_KEY *priv = pkey("/tmp/skey.pem", 0);
	EC_KEY *publ = pkey("/tmp/ckey.pem", 1);

	srand(time(NULL));

	if ((!priv) || (!publ)) {
		perror("Failed to read keys\n");
		return 1;
	}


	printf("\n");


	rnds(zstr, 96, 384);
	BN_hex2bn(&znum, zstr);
	sigz = sign(publ, (unsigned char *)zstr, strlen(zstr), NULL);
	printf("tx publ sign: %s = (%s, %s)\n\t\t%s\n", zstr, sigz[0], sigz[1], sigz[2]);


	zsig = vrfy(priv, sigz[0], sigz[1], sigz[2], NULL);
	ptsz = pmul(priv, zsig, NULL);
	zpnt = xpyp(priv, ptsz[0], ptsz[1]);
	printf("rx priv vrfy: %s\n", zsig);


	printf("\n");


	rnds(cstr, 96, 384);
	ptsa = pmul(publ, cstr, NULL);
	siga = sign(publ, (unsigned char *)ptsa[0], strlen(ptsa[0]), NULL);
	sigc = sign(publ, (unsigned char *)ptsa[1], strlen(ptsa[1]), NULL);
	printf("tx publ dhkx: %s = (%s, %s)\n", cstr, ptsa[0], ptsa[1]);
	printf("tx publ sign: %s = (%s, %s)\n\t\t%s\n", "*", siga[0], siga[1], siga[2]);
	printf("tx publ sign: %s = (%s, %s)\n\t\t%s\n", "*", sigc[0], sigc[1], sigc[2]);


	printf("\n");


	rnds(sstr, 96, 384);
	ptsb = pmul(priv, sstr, NULL);
	sigb = sign(priv, (unsigned char *)ptsb[0], strlen(ptsb[0]), zpnt);
	sigd = sign(priv, (unsigned char *)ptsb[1], strlen(ptsb[1]), zpnt);
	printf("tx priv dhkx: %s = (%s, %s)\n", sstr, ptsb[0], ptsb[1]);
	printf("tx priv sign: %s = (%s, %s)\n\t\t%s\n", "*", sigb[0], sigb[1], sigb[2]);
	printf("tx priv sign: %s = (%s, %s)\n\t\t%s\n", "*", sigd[0], sigd[1], sigd[2]);


	printf("\n");


	bsig = vrfy(publ, sigb[0], sigb[1], sigb[2], znum);
	dsig = vrfy(publ, sigd[0], sigd[1], sigd[2], znum);
	spnt = xpyp(publ, bsig, dsig);
	ptsc = pmul(publ, cstr, spnt);
	printf("rx publ vrfy: (%s, %s)\n", bsig, dsig);
	printf("rx publ dhkx: %s = (%s, %s)\n", cstr, ptsc[0], ptsc[1]);


	printf("\n");


	asig = vrfy(priv, siga[0], siga[1], siga[2], NULL);
	csig = vrfy(priv, sigc[0], sigc[1], sigc[2], NULL);
	cpnt = xpyp(priv, asig, csig);
	ptsd = pmul(priv, sstr, cpnt);
	printf("rx priv vrfy: (%s, %s)\n", asig, csig);
	printf("rx priv dhkx: %s = (%s, %s)\n", sstr, ptsd[0], ptsd[1]);


	printf("\n");


	free(ptsa[1]); free(ptsa[0]); free(ptsa);
	free(ptsb[1]); free(ptsb[0]); free(ptsb);
	free(ptsc[1]); free(ptsc[0]); free(ptsc);
	free(ptsd[1]); free(ptsd[0]); free(ptsd);
	free(ptsz[1]); free(ptsz[0]); free(ptsz);
	free(siga[3]); free(siga[2]); free(siga[1]); free(siga[0]); free(siga);
	free(sigb[3]); free(sigb[2]); free(sigb[1]); free(sigb[0]); free(sigb);
	free(sigc[3]); free(sigc[2]); free(sigc[1]); free(sigc[0]); free(sigc);
	free(sigd[3]); free(sigd[2]); free(sigd[1]); free(sigd[0]); free(sigd);
	free(sigz[3]); free(sigz[2]); free(sigz[1]); free(sigz[0]); free(sigz);
	free(asig); free(bsig); free(csig); free(dsig); free(zsig);
	BN_free(znum);
	EC_POINT_free(spnt); EC_POINT_free(cpnt); EC_POINT_free(zpnt);
	EC_KEY_free(publ); EC_KEY_free(priv);
	return 0;
}
