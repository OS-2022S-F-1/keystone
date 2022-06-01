//******************************************************************************
// Copyright (c) 2018, The Regents of the University of California (Regents).
// All Rights Reserved. See LICENSE for license details.
//------------------------------------------------------------------------------
#include "ipi.h"
#include "sm.h"
#include "pmp.h"
#include "crypto.h"
#include "enclave.h"
#include "platform-hook.h"
#include "sm-sbi-opensbi.h"
#include "sha3/sha3.h"
#include "ed25519/ed25519.h"
#include <sbi/sbi_string.h>
#include <sbi/riscv_locks.h>
#include <sbi/riscv_barrier.h>
#include <sbi/sbi_console.h>
#include <sbi/sbi_hart.h>

#define DRAM_BASE 0x80000000

static int sm_init_done = 0;
static int sm_region_id = 0, os_region_id = 0;

/* from Sanctum BootROM */
extern byte sanctum_sm_hash[MDSIZE];
extern byte sanctum_dev_secret_key[PRIVATE_KEY_SIZE];
extern byte sanctum_sm_signature[SIGNATURE_SIZE];
extern byte sanctum_sm_secret_key[PRIVATE_KEY_SIZE];
extern byte sanctum_sm_public_key[PUBLIC_KEY_SIZE];
extern byte sanctum_dev_public_key[PUBLIC_KEY_SIZE];
unsigned int sanctum_sm_size = 0x1ff000;

byte sm_hash[MDSIZE] = { 0, };
byte sm_signature[SIGNATURE_SIZE] = { 0, };
byte sm_public_key[PUBLIC_KEY_SIZE] = { 0, };
byte sm_private_key[PRIVATE_KEY_SIZE] = { 0, };
byte dev_public_key[PUBLIC_KEY_SIZE] = { 0, };

inline byte random_byte(unsigned int i) {
    return 0xac + (0xdd ^ i);
}

void bootloader() {
    byte scratchpad[128];
    sha3_ctx_t hash_ctx;

    // TODO: on real device, copy boot image from memory. In simulator, HTIF writes boot image
    // ... SD card to beginning of memory.
    // sd_init();
    // sd_read_from_start(DRAM, 1024);

    /* Gathering high quality entropy during boot on embedded devices is
     * a hard problem. Platforms taking security seriously must provide
     * a high quality entropy source available in hardware. Platforms
     * that do not provide such a source must gather their own
     * entropy. See the Keystone documentation for further
     * discussion. For testing purposes, we have no entropy generation.
    */

    // Create a random seed for keys and nonces from TRNG
    for (unsigned int i=0; i<32; i++) {
        scratchpad[i] = random_byte(i);
    }

    /* On a real device, the platform must provide a secure root device
       keystore. For testing purposes we hardcode a known private/public
       keypair */
    // Derive {SK_D, PK_D} (device keys) from a 32 B random seed
    //ed25519_create_keypair(sanctum_dev_public_key, sanctum_dev_secret_key, scratchpad);

    // Measure SM
    sha3_init(&hash_ctx, 64);
    sha3_update(&hash_ctx, (void*)DRAM_BASE, sanctum_sm_size);
    sha3_final(sanctum_sm_hash, &hash_ctx);

    // Combine SK_D and H_SM via a hash
    // sm_key_seed <-- H(SK_D, H_SM), truncate to 32B
    sha3_init(&hash_ctx, 64);
    sha3_update(&hash_ctx, sanctum_dev_secret_key, sizeof(*sanctum_dev_secret_key));
    sha3_update(&hash_ctx, sanctum_sm_hash, sizeof(*sanctum_sm_hash));
    sha3_final(scratchpad, &hash_ctx);
    // Derive {SK_D, PK_D} (device keys) from the first 32 B of the hash (NIST endorses SHA512 truncation as safe)
    ed25519_create_keypair(sanctum_sm_public_key, sanctum_sm_secret_key, scratchpad);

    // Endorse the SM
    sbi_memcpy(scratchpad, sanctum_sm_hash, 64);
    sbi_memcpy(scratchpad + 64, sanctum_sm_public_key, 32);
    // Sign (H_SM, PK_SM) with SK_D
    ed25519_sign(sanctum_sm_signature, scratchpad, 64 + 32, sanctum_dev_public_key, sanctum_dev_secret_key);

    // Clean up
    // Erase SK_D
    sbi_memset((void*)sanctum_dev_secret_key, 0, sizeof(*sanctum_sm_secret_key));

    // caller will clean core state and memory (including the stack), and boot.
    return;
}

int osm_pmp_set(uint8_t perm)
{
  /* in case of OSM, PMP cfg is exactly the opposite.*/
  return pmp_set_keystone(os_region_id, perm);
}

int smm_init()
{
  int region = -1;
  int ret = pmp_region_init_atomic(SMM_BASE, SMM_SIZE, PMP_PRI_TOP, &region, 0);
  if(ret)
    return -1;

  return region;
}

int osm_init()
{
  int region = -1;
  int ret = pmp_region_init_atomic(0, -1UL, PMP_PRI_BOTTOM, &region, 1);
  if(ret)
    return -1;

  return region;
}

void sm_sign(void* signature, const void* data, size_t len)
{
  sign(signature, data, len, sm_public_key, sm_private_key);
}

int sm_derive_sealing_key(unsigned char *key, const unsigned char *key_ident,
                          size_t key_ident_size,
                          const unsigned char *enclave_hash)
{
  unsigned char info[MDSIZE + key_ident_size];

  sbi_memcpy(info, enclave_hash, MDSIZE);
  sbi_memcpy(info + MDSIZE, key_ident, key_ident_size);

  /*
   * The key is derived without a salt because we have no entropy source
   * available to generate the salt.
   */
  return kdf(NULL, 0,
             (const unsigned char *)sm_private_key, PRIVATE_KEY_SIZE,
             info, MDSIZE + key_ident_size, key, SEALING_KEY_SIZE);
}

void sm_copy_key()
{
  sbi_memcpy(sm_hash, sanctum_sm_hash, MDSIZE);
  sbi_memcpy(sm_signature, sanctum_sm_signature, SIGNATURE_SIZE);
  sbi_memcpy(sm_public_key, sanctum_sm_public_key, PUBLIC_KEY_SIZE);
  sbi_memcpy(sm_private_key, sanctum_sm_secret_key, PRIVATE_KEY_SIZE);
  sbi_memcpy(dev_public_key, sanctum_dev_public_key, PUBLIC_KEY_SIZE);
}

/*
void sm_print_cert()
{
	int i;

	printm("Booting from Security Monitor\n");
	printm("Size: %d\n", sanctum_sm_size[0]);

	printm("============ PUBKEY =============\n");
	for(i=0; i<8; i+=1)
	{
		printm("%x",*((int*)sanctum_dev_public_key+i));
		if(i%4==3) printm("\n");
	}
	printm("=================================\n");

	printm("=========== SIGNATURE ===========\n");
	for(i=0; i<16; i+=1)
	{
		printm("%x",*((int*)sanctum_sm_signature+i));
		if(i%4==3) printm("\n");
	}
	printm("=================================\n");
}
*/

void sm_init(bool cold_boot)
{
    bootloader();
	// initialize SMM
  if (cold_boot) {
    /* only the cold-booting hart will execute these */
    sbi_printf("[SM] Initializing ... hart [%lx]\n", csr_read(mhartid));

    sbi_ecall_register_extension(&ecall_keystone_enclave);

    sm_region_id = smm_init();
    if(sm_region_id < 0) {
      sbi_printf("[SM] intolerable error - failed to initialize SM memory");
      sbi_hart_hang();
    }

    os_region_id = osm_init();
    if(os_region_id < 0) {
      sbi_printf("[SM] intolerable error - failed to initialize OS memory");
      sbi_hart_hang();
    }

    if (platform_init_global_once() != SBI_ERR_SM_ENCLAVE_SUCCESS) {
      sbi_printf("[SM] platform global init fatal error");
      sbi_hart_hang();
    }
    // Copy the keypair from the root of trust
    sm_copy_key();

    // Init the enclave metadata
    enclave_init_metadata();

    sm_init_done = 1;
    mb();
  }

  /* wait until cold-boot hart finishes */
  while (!sm_init_done)
  {
    mb();
  }

  /* below are executed by all harts */
  pmp_init();
  pmp_set_keystone(sm_region_id, PMP_NO_PERM);
  pmp_set_keystone(os_region_id, PMP_ALL_PERM);

  /* Fire platform specific global init */
  if (platform_init_global() != SBI_ERR_SM_ENCLAVE_SUCCESS) {
    sbi_printf("[SM] platform global init fatal error");
    sbi_hart_hang();
  }

  sbi_printf("[SM] Keystone security monitor has been initialized!\n");

  return;
  // for debug
  // sm_print_cert();
}
