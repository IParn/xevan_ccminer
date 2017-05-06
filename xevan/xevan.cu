/*
 * X17 algorithm built on cbuchner1's original X11
 *
 */

extern "C"
{
#include "sph/sph_blake.h"
#include "sph/sph_bmw.h"
#include "sph/sph_groestl.h"
#include "sph/sph_skein.h"
#include "sph/sph_jh.h"
#include "sph/sph_keccak.h"

#include "sph/sph_luffa.h"
#include "sph/sph_cubehash.h"
#include "sph/sph_shavite.h"
#include "sph/sph_simd.h"
#include "sph/sph_echo.h"

#include "sph/sph_hamsi.h"
#include "sph/sph_fugue.h"

#include "sph/sph_shabal.h"
#include "sph/sph_whirlpool.h"

#include "sph/sph_sha2.h"
#include "sph/sph_haval.h"
}

#include "miner.h"
#include "cuda_helper.h"

static uint32_t *d_hash[MAX_GPUS];
static uint32_t endiandata[MAX_GPUS][20];


extern void quark_blake512_cpu_init(int thr_id);
extern void quark_blake512_cpu_setBlock_80(uint64_t *pdata);
extern void quark_blake512_cpu_setBlock_80_multi(uint32_t thr_id, uint64_t *pdata);
extern void quark_blake512_cpu_hash_80(uint32_t threads, uint32_t startNounce, uint32_t *d_hash);

extern void quark_bmw512_cpu_hash_64(uint32_t threads, uint32_t startNounce, uint32_t *d_nonceVector, uint32_t *d_hash);

extern void quark_groestl512_cpu_hash_64(uint32_t threads, uint32_t startNounce, uint32_t *d_nonceVector, uint32_t *d_hash);

extern void quark_skein512_cpu_init(int thr_id);
extern void quark_skein512_cpu_hash_64(uint32_t threads, uint32_t startNounce, uint32_t *d_nonceVector, uint32_t *d_hash);

extern void cuda_jh512Keccak512_cpu_hash_64(uint32_t threads, uint32_t startNounce, uint32_t *d_hash);

extern void x11_luffaCubehash512_cpu_hash_64(uint32_t threads, uint32_t startNounce, uint32_t *d_hash, uint32_t luffacubethreads);

extern void x11_shavite512_cpu_hash_64(uint32_t threads, uint32_t startNounce, uint32_t *d_hash, uint32_t shavitethreads);

extern int  x11_simd512_cpu_init(int thr_id, uint32_t threads);
extern void x11_simd512_cpu_hash_64(int thr_id, uint32_t threads, uint32_t startNounce, uint32_t *d_hash, const uint32_t simdthreads);

extern void x11_echo512_cpu_init(int thr_id, uint32_t threads);
extern void x11_echo512_cpu_hash_64(int thr_id, uint32_t threads, uint32_t startNounce, uint32_t *d_hash);

extern void x13_hamsi512_cpu_init(int thr_id, uint32_t threads);
extern void x13_hamsi512_cpu_hash_64(uint32_t threads, uint32_t startNounce, uint32_t *d_hash);

extern void x13_fugue512_cpu_init(int thr_id, uint32_t threads);
extern void x13_fugue512_cpu_hash_64(int thr_id, uint32_t threads, uint32_t startNounce, uint32_t *d_hash);

extern void x14_shabal512_cpu_hash_64(int thr_id, uint32_t threads, uint32_t startNounce, uint32_t *d_hash);

extern void x15_whirlpool_cpu_init(int thr_id, uint32_t threads, int flag);
extern void x15_whirlpool_cpu_hash_64(int thr_id, uint32_t threads, uint32_t startNounce, uint32_t *d_hash);

extern void x17_sha512_cpu_init(int thr_id, uint32_t threads);
extern void x17_sha512_cpu_hash_64(int thr_id, uint32_t threads, uint32_t startNounce,uint32_t *d_hash);

extern void x17_haval256_cpu_init(int thr_id, uint32_t threads);
extern void x17_haval256_cpu_hash_64(int thr_id, uint32_t threads, uint32_t startNounce, uint32_t *d_hash);

extern void quark_compactTest_cpu_init(int thr_id, uint32_t threads);
extern void quark_compactTest_cpu_hash_64(int thr_id, uint32_t threads, uint32_t startNounce, uint32_t *inpHashes,
											uint32_t *d_noncesTrue, uint32_t *nrmTrue, uint32_t *d_noncesFalse, uint32_t *nrmFalse);

// Xevan
extern "C" void xevan_hash(void *output, const void *input)
{
	// blake1-bmw2-grs3-skein4-jh5-keccak6-luffa7-cubehash8-shavite9-simd10-echo11-hamsi12-fugue13-shabal14-whirlpool15-sha512-haval17

	sph_blake512_context ctx_blake;
	sph_bmw512_context ctx_bmw;
	sph_groestl512_context ctx_groestl;
	sph_jh512_context ctx_jh;
	sph_keccak512_context ctx_keccak;
	sph_skein512_context ctx_skein;
	sph_luffa512_context ctx_luffa;
	sph_cubehash512_context ctx_cubehash;
	sph_shavite512_context ctx_shavite;
	sph_simd512_context ctx_simd;
	sph_echo512_context ctx_echo;
	sph_hamsi512_context ctx_hamsi;
	sph_fugue512_context ctx_fugue;
	sph_shabal512_context ctx_shabal;
	sph_whirlpool_context ctx_whirlpool;
	sph_sha512_context ctx_sha512;
	sph_haval256_5_context ctx_haval;

	uint32_t hashA[32], hashB[32];
	memset(hashA , 0, 128);
	memset(hashB , 0, 128);

    sph_blake512_init(&ctx_blake);
    sph_blake512 (&ctx_blake, input, 80);
    sph_blake512_close (&ctx_blake, hashA);

    sph_bmw512_init(&ctx_bmw);
    sph_bmw512 (&ctx_bmw, hashA, 128);
    sph_bmw512_close(&ctx_bmw, hashB);

    sph_groestl512_init(&ctx_groestl);
    sph_groestl512 (&ctx_groestl, hashB, 128);
    sph_groestl512_close(&ctx_groestl, hashA);

    sph_skein512_init(&ctx_skein);
    sph_skein512 (&ctx_skein, hashA, 128);
    sph_skein512_close (&ctx_skein, hashB);

    sph_jh512_init(&ctx_jh);
    sph_jh512 (&ctx_jh, hashB, 128);
    sph_jh512_close(&ctx_jh, hashA);

    sph_keccak512_init(&ctx_keccak);
    sph_keccak512 (&ctx_keccak, hashA, 128);
    sph_keccak512_close(&ctx_keccak, hashB);

    sph_luffa512_init (&ctx_luffa1);
    sph_luffa512 (&ctx_luffa1, hashB, 128);
    sph_luffa512_close (&ctx_luffa1, hashA);

    sph_cubehash512_init (&ctx_cubehash1);
    sph_cubehash512 (&ctx_cubehash1, hashA, 128);
    sph_cubehash512_close(&ctx_cubehash1, hashB);

    sph_shavite512_init (&ctx_shavite1);
    sph_shavite512 (&ctx_shavite1, hashB, 128);
    sph_shavite512_close(&ctx_shavite1, hashA);

    sph_simd512_init (&ctx_simd1);
    sph_simd512 (&ctx_simd1, hashA, 128);
    sph_simd512_close(&ctx_simd1, hashB);

    sph_echo512_init (&ctx_echo1);
    sph_echo512 (&ctx_echo1, hashB, 128);
    sph_echo512_close(&ctx_echo1, hashA);
	
	
	sph_hamsi512_init(&ctx_hamsi);
    sph_hamsi512 (&ctx_hamsi, hashA, 128);
    sph_hamsi512_close(&ctx_hamsi, hashB);

    sph_fugue512_init(&ctx_fugue);
    sph_fugue512 (&ctx_fugue, hashB, 128);
    sph_fugue512_close(&ctx_fugue, hashA);

    sph_shabal512_init(&ctx_shabal);
    sph_shabal512 (&ctx_shabal, hashA, 128);
    sph_shabal512_close(&ctx_shabal, hashB);

    sph_whirlpool_init(&ctx_whirlpool);
    sph_whirlpool (&ctx_whirlpool, hashB, 128);
    sph_whirlpool_close(&ctx_whirlpool, hashA);

    sph_sha512_init(&ctx_sha2);
    sph_sha512 (&ctx_sha2, hashA, 128);
    sph_sha512_close(&ctx_sha2, hashB);

    sph_haval256_5_init(&ctx_haval);
    sph_haval256_5 (&ctx_haval, hashB, 128);
    sph_haval256_5_close(&ctx_haval, hashA);
	memset(&hashA[8], 0, 128 - 32);
	
	
    ///  Part2
    sph_blake512_init(&ctx_blake);
    sph_blake512 (&ctx_blake, hashA, 128);
    sph_blake512_close(&ctx_blake, hashB);
    
    sph_bmw512_init(&ctx_bmw);
    sph_bmw512 (&ctx_bmw, hashB, 128);
    sph_bmw512_close(&ctx_bmw, hashA);

    sph_groestl512_init(&ctx_groestl);
    sph_groestl512 (&ctx_groestl, hashA, 128);
    sph_groestl512_close(&ctx_groestl, hashB);

    sph_skein512_init(&ctx_skein);
    sph_skein512 (&ctx_skein, hashB, 128);
    sph_skein512_close(&ctx_skein, hashA);
    
    sph_jh512_init(&ctx_jh);
    sph_jh512 (&ctx_jh, hashA, 128);
    sph_jh512_close(&ctx_jh, hashB);
    
    sph_keccak512_init(&ctx_keccak);
    sph_keccak512 (&ctx_keccak, hashB, 128);
    sph_keccak512_close(&ctx_keccak, hashA);

    sph_luffa512_init(&ctx_luffa1);
    sph_luffa512 (&ctx_luffa1, hashA, 128);
    sph_luffa512_close(&ctx_luffa1, hashB);
    
    sph_cubehash512_init(&ctx_cubehash1);
    sph_cubehash512 (&ctx_cubehash1, hashB, 128);
    sph_cubehash512_close(&ctx_cubehash1, hashA);
    
    sph_shavite512_init(&ctx_shavite1);
    sph_shavite512(&ctx_shavite1, hashA, 128);
    sph_shavite512_close(&ctx_shavite1, hashB);
        
    sph_simd512_init(&ctx_simd1);
    sph_simd512 (&ctx_simd1, hashB, 128);
    sph_simd512_close(&ctx_simd1, hashA);

    sph_echo512_init(&ctx_echo1);
    sph_echo512 (&ctx_echo1, hashA, 128);
    sph_echo512_close(&ctx_echo1, hashB);

    sph_hamsi512_init(&ctx_hamsi);
    sph_hamsi512 (&ctx_hamsi, hashB, 128);
    sph_hamsi512_close(&ctx_hamsi, hashA);

    sph_fugue512_init(&ctx_fugue);
    sph_fugue512 (&ctx_fugue, hashA, 128);
    sph_fugue512_close(&ctx_fugue, hashB);

    sph_shabal512_init(&ctx_shabal);
    sph_shabal512 (&ctx_shabal, hashB, 128);
    sph_shabal512_close(&ctx_shabal, hashA);

    sph_whirlpool_init(&ctx_whirlpool);
    sph_whirlpool (&ctx_whirlpool, hashA, 128);
    sph_whirlpool_close(&ctx_whirlpool, hashB);

    sph_sha512_init(&ctx_sha2);
    sph_sha512 (&ctx_sha2, hashB, 128);
    sph_sha512_close(&ctx_sha2, hashA);

    sph_haval256_5_init(&ctx_haval);
    sph_haval256_5 (&ctx_haval, hashA, 128);
    sph_haval256_5_close(&ctx_haval, hashB);


    memcpy(output, hashB, 32);
}

static bool init[MAX_GPUS] = { 0 };

extern "C" int scanhash_x17(int thr_id, uint32_t *pdata,
	const uint32_t *ptarget, uint32_t max_nonce,
	unsigned long *hashes_done)
{
	const uint32_t first_nonce = pdata[19];

	int intensity = 256 * 256 * 13;
	if (device_sm[device_map[thr_id]] == 520)  intensity = 256 * 256 * 22;
	uint32_t throughput = device_intensity(device_map[thr_id], __func__, intensity); // 19=256*256*8;
	throughput = min(throughput, (max_nonce - first_nonce));
	uint32_t simdthreads = (device_sm[device_map[thr_id]] > 500) ? 64 : 32;
	uint32_t shavitethreads = (device_sm[device_map[thr_id]] == 500) ? 256 : 320;
	uint32_t luffacubehashthreads = (device_sm[device_map[thr_id]] == 500) ? 512 : 256;

	if (opt_benchmark)
		((uint32_t*)ptarget)[7] = 0xff;

	if (!init[thr_id])
	{
		cudaSetDevice(device_map[thr_id]);
		if (!opt_cpumining) cudaSetDeviceFlags(cudaDeviceScheduleBlockingSync);
		if (opt_n_gputhreads == 1)
		{
			cudaDeviceSetCacheConfig(cudaFuncCachePreferL1);
		}
		cudaDeviceSetCacheConfig(cudaFuncCachePreferL1);

		quark_skein512_cpu_init(thr_id);
		x11_simd512_cpu_init(thr_id, throughput);
		x11_echo512_cpu_init(thr_id, throughput);
		x13_hamsi512_cpu_init(thr_id, throughput);
		x13_fugue512_cpu_init(thr_id, throughput);
		x15_whirlpool_cpu_init(thr_id, throughput, 0);
		x17_sha512_cpu_init(thr_id, throughput);
		x17_haval256_cpu_init(thr_id, throughput);

		CUDA_CALL_OR_RET_X(cudaMalloc(&d_hash[thr_id], 16 * sizeof(uint32_t) * throughput), 0);
		quark_blake512_cpu_init(thr_id);

		cuda_check_cpu_init(thr_id, throughput);
		init[thr_id] = true;
	}

	for (int k = 0; k < 20; k++)
		be32enc(&endiandata[thr_id][k], ((uint32_t*)pdata)[k]);

	if (opt_n_gputhreads > 1)
	{
		quark_blake512_cpu_setBlock_80_multi(thr_id, (uint64_t *)endiandata[thr_id]);
	}
	else
	{
		quark_blake512_cpu_setBlock_80((uint64_t *)endiandata[thr_id]);
	}
	cuda_check_cpu_setTarget(ptarget);

	do {

		quark_blake512_cpu_hash_80(throughput, pdata[19], d_hash[thr_id]);
		quark_bmw512_cpu_hash_64(throughput, pdata[19], NULL, d_hash[thr_id]);
		quark_groestl512_cpu_hash_64(throughput, pdata[19], NULL, d_hash[thr_id]);
		quark_skein512_cpu_hash_64(throughput, pdata[19], NULL, d_hash[thr_id]);
		cuda_jh512Keccak512_cpu_hash_64(throughput, pdata[19], d_hash[thr_id]);

		x11_luffaCubehash512_cpu_hash_64(throughput, pdata[19], d_hash[thr_id], luffacubehashthreads);
		x11_shavite512_cpu_hash_64(throughput, pdata[19], d_hash[thr_id], shavitethreads);
		x11_simd512_cpu_hash_64(thr_id, throughput, pdata[19], d_hash[thr_id], simdthreads);
		x11_echo512_cpu_hash_64(thr_id, throughput, pdata[19], d_hash[thr_id]);
		x13_hamsi512_cpu_hash_64(throughput, pdata[19], d_hash[thr_id]);
		x13_fugue512_cpu_hash_64(thr_id, throughput, pdata[19], d_hash[thr_id]);
		x14_shabal512_cpu_hash_64(thr_id, throughput, pdata[19], d_hash[thr_id]);
		x15_whirlpool_cpu_hash_64(thr_id, throughput, pdata[19], d_hash[thr_id]);
		x17_sha512_cpu_hash_64(thr_id, throughput, pdata[19], d_hash[thr_id]);
		x17_haval256_cpu_hash_64(thr_id, throughput, pdata[19], d_hash[thr_id]);

		uint32_t foundNonce = cuda_check_hash(thr_id, throughput, pdata[19], d_hash[thr_id]);
		if (foundNonce != UINT32_MAX)
		{
			const uint32_t Htarg = ptarget[7];
			uint32_t vhash64[8];
			/* check now with the CPU to confirm */
			be32enc(&endiandata[thr_id][19], foundNonce);
			x17hash(vhash64, endiandata[thr_id]);

			if (vhash64[7] <= Htarg && fulltest(vhash64, ptarget)) {
				int res = 1;
				uint32_t secNonce = cuda_check_hash_suppl(thr_id, throughput, pdata[19], d_hash[thr_id], foundNonce);
				*hashes_done = pdata[19] - first_nonce + throughput;
				if (secNonce != 0) {
					pdata[21] = secNonce;
					res++;
				}
				if (opt_benchmark) applog(LOG_INFO, "found nounce", thr_id, foundNonce, vhash64[7], Htarg);
				pdata[19] = foundNonce;
				return res;
			}
			else
			{
				applog(LOG_INFO, "GPU #%d: result for %08x does not validate on CPU!", thr_id, foundNonce);
			}
		}

		pdata[19] += throughput;
	} while (!scan_abort_flag && !work_restart[thr_id].restart && ((uint64_t)max_nonce > ((uint64_t)(pdata[19]) + (uint64_t)throughput)));

	*hashes_done = pdata[19] - first_nonce;
	return 0;
}
