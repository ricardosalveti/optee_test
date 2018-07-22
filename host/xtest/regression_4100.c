/*
 * Copyright (c) 2018, Linaro Limited
 * Copyright (c) 2014, STMicroelectronics International N.V.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License Version 2 as
 * published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU General Public License for more details.
 */

#include <assert.h>
#include <inttypes.h>
#include <malloc.h>
#include <pkcs11.h>
#include <sks_ck_debug.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ta_crypt.h>
#include <tee_api_types.h>
#include <utee_defines.h>
#include <util.h>

#include "xtest_test.h"
#include "xtest_helpers.h"

/*
 * Some PKCS#11 object resources used in the tests
 */
static const CK_BYTE cktest_aes128_key[16];

static const CK_BYTE cktest_aes128_iv[16];

static const CK_AES_CTR_PARAMS cktest_aes_ctr_params = {
	.ulCounterBits = 1,
};

static CK_MECHANISM cktest_aes_ecb_mechanism = {
	CKM_AES_ECB,
	NULL, 0,
};
static CK_MECHANISM cktest_aes_cbc_mechanism = {
	CKM_AES_CBC,
	(CK_BYTE_PTR)cktest_aes128_iv, sizeof(cktest_aes128_iv),
};
static CK_MECHANISM cktest_aes_ctr_mechanism = {
	CKM_AES_CTR,
	(CK_BYTE_PTR)&cktest_aes_ctr_params, sizeof(cktest_aes_ctr_params),
};
static CK_MECHANISM cktest_aes_cts_mechanism = {
	CKM_AES_CTS,
	(CK_BYTE_PTR)cktest_aes128_iv, sizeof(cktest_aes128_iv),
};

static CK_BYTE dummy_1kbyte_buffer[1024];

static CK_CCM_PARAMS cktest_aes_ccm_mechanism_params =	{
	.ulDataLen = 0,
	.pNonce = (CK_BYTE_PTR)dummy_1kbyte_buffer,
	.ulNonceLen = 8,
	.pAAD = (CK_BYTE_PTR)dummy_1kbyte_buffer,
	.ulAADLen = 16,
	.ulMACLen = 6,
};

static CK_MECHANISM cktest_aes_ccm_mechanism = {
	CKM_AES_CCM,
	(CK_BYTE_PTR)&cktest_aes_ccm_mechanism_params,
	sizeof(cktest_aes_ccm_mechanism_params),
};

static CK_GCM_PARAMS cktest_aes_gcm_mechanism_params = {
	.pIv = (CK_BYTE_PTR)dummy_1kbyte_buffer,
	.ulIvLen = 8,
	.pAAD = (CK_BYTE_PTR)dummy_1kbyte_buffer,
	.ulAADLen =  20,
	.ulTagBits = 128,
};

static CK_MECHANISM cktest_aes_gcm_mechanism = {
	CKM_AES_GCM,
	(CK_BYTE_PTR)&cktest_aes_gcm_mechanism_params,
	sizeof(cktest_aes_gcm_mechanism_params),
};

/*
 * Util to find a slot on which to open a session
 */
static CK_RV close_lib(void)
{
	return C_Finalize(0);
}

static CK_RV init_lib_and_find_token_slot(CK_SLOT_ID *slot)
{
	CK_RV rv;
	CK_SLOT_ID_PTR slots = NULL;
	CK_ULONG count;

	rv = C_Initialize(0);
	if (rv)
		return rv;

	rv = C_GetSlotList(CK_TRUE, NULL, &count);
	if (rv != CKR_OK)
		goto bail;

	if (count < 1) {
		rv = CKR_GENERAL_ERROR;
		goto bail;
	}

	slots = malloc(count * sizeof(CK_SLOT_ID));
	if (!slots) {
		rv = CKR_HOST_MEMORY;
		goto bail;
	}

	rv = C_GetSlotList(CK_TRUE, slots, &count);
	if (rv)
		goto bail;

	/* Use the last slot */
	*slot = slots[count - 1];

bail:
	free(slots);
	if (rv)
		close_lib();

	return rv;
}

/* Login currently as SO, uzer login not yet supported */
static char test_token_so_pin[] = { 0, 1, 2, 3, 4, 5, 6, 7, 8 };
static char test_token_user_pin[] = { 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11 };
static char test_token_label[32] = "sks test token";

static CK_RV init_test_token(CK_SLOT_ID slot)
{
	return C_InitToken(slot,
			   (CK_UTF8CHAR_PTR)test_token_so_pin,
			   sizeof(test_token_so_pin),
			   (CK_UTF8CHAR_PTR)test_token_label);
}

static CK_RV init_user_test_token(CK_SLOT_ID slot)
{
	CK_FLAGS session_flags = CKF_SERIAL_SESSION | CKF_RW_SESSION;
	CK_SESSION_HANDLE session;
	CK_RV rv;

	rv = C_OpenSession(slot, session_flags, NULL, 0, &session);
	if (rv)
		return rv;

	rv = C_Login(session, CKU_USER,	(CK_UTF8CHAR_PTR)test_token_user_pin,
					sizeof(test_token_user_pin));
	if (rv == CKR_OK) {
		C_Logout(session);
		C_CloseSession(session);
		return rv;
	}

	rv = C_Login(session, CKU_SO, (CK_UTF8CHAR_PTR)test_token_so_pin,
					sizeof(test_token_so_pin));
	if (rv) {
		C_CloseSession(session);

		rv = init_test_token(slot);
		if (rv)
			return rv;

		rv = C_OpenSession(slot, session_flags, NULL, 0, &session);
		if (rv)
			return rv;

		rv = C_Login(session, CKU_SO, (CK_UTF8CHAR_PTR)test_token_so_pin,
					sizeof(test_token_so_pin));
		if (rv) {
			C_CloseSession(session);
			return rv;
		}
	}

	rv = C_InitPIN(session, (CK_UTF8CHAR_PTR)test_token_user_pin,
				sizeof(test_token_user_pin));

	C_Logout(session);
	C_CloseSession(session);

	return rv;
}

CK_RV login_so_test_token(CK_SESSION_HANDLE session);
CK_RV login_so_test_token(CK_SESSION_HANDLE session)
{
	return C_Login(session, CKU_SO, (CK_UTF8CHAR_PTR)test_token_so_pin,
				sizeof(test_token_so_pin));
}

CK_RV login_user_test_token(CK_SESSION_HANDLE session);
CK_RV login_user_test_token(CK_SESSION_HANDLE session)
{
	return C_Login(session, CKU_USER, (CK_UTF8CHAR_PTR)test_token_user_pin,
				sizeof(test_token_user_pin));
}

CK_RV login_context_test_token(CK_SESSION_HANDLE session);
CK_RV login_context_test_token(CK_SESSION_HANDLE session)
{
	return C_Login(session, CKU_CONTEXT_SPECIFIC,
			(CK_UTF8CHAR_PTR)test_token_user_pin,
			sizeof(test_token_user_pin));
}

CK_RV logout_test_token(CK_SESSION_HANDLE session);
CK_RV logout_test_token(CK_SESSION_HANDLE session)
{
	return C_Logout(session);
}

/*
 * The test below belongs to the regression 41xx test. As it rely on test
 * vectors define for the 40xx test, this test sequence in implemented here.
 * The test below check compliance of crypto algorithms called throug the SKS
 * PKCS#11 interface.
 */
void run_xtest_tee_test_4110(ADBG_Case_t *c, CK_SLOT_ID slot);
void run_xtest_tee_test_4111(ADBG_Case_t *c, CK_SLOT_ID slot);
void run_xtest_tee_test_4112(ADBG_Case_t *c, CK_SLOT_ID slot);
void run_xtest_tee_test_4116(ADBG_Case_t *c, CK_SLOT_ID slot);
void run_xtest_tee_test_4117(ADBG_Case_t *c, CK_SLOT_ID slot);

static void cktest_in_regression_40xx(ADBG_Case_t *c, int test_id)
{
	CK_RV rv;
	CK_SLOT_ID slot;
	CK_SESSION_HANDLE session = CK_INVALID_HANDLE;
	CK_FLAGS session_flags = CKF_SERIAL_SESSION;

	rv = init_lib_and_find_token_slot(&slot);
	if (!ADBG_EXPECT_CK_OK(c, rv))
		return;

	rv = init_user_test_token(slot);
	if (!ADBG_EXPECT_CK_OK(c, rv))
		goto bail;

	rv = C_OpenSession(slot, session_flags, NULL, 0, &session);
	if (!ADBG_EXPECT_CK_OK(c, rv))
		goto bail;

	rv = login_user_test_token(session);
	if (!ADBG_EXPECT_CK_OK(c, rv))
		goto bail;

	switch (test_id) {
	case 4110:
		run_xtest_tee_test_4110(c, slot);
		break;
	case 4111:
		run_xtest_tee_test_4111(c, slot);
		break;
	case 4112:
		run_xtest_tee_test_4112(c, slot);
		break;
	case 4116:
		run_xtest_tee_test_4116(c, slot);
		break;
	case 4117:
		run_xtest_tee_test_4117(c, slot);
		break;
	default:
		ADBG_EXPECT_TRUE(c, false);
		break;
	}

bail:
	if (session != CK_INVALID_HANDLE) {
		logout_test_token(session);
		C_CloseSession(session);
	}
	close_lib();
}

static void xtest_tee_test_4101(ADBG_Case_t *c)
{
	CK_RV rv;

	rv = C_Initialize(NULL);
	if (!ADBG_EXPECT_CK_OK(c, rv))
		return;

	rv = C_Finalize(NULL);
	if (!ADBG_EXPECT_CK_OK(c, rv))
		return;

	rv = C_Initialize(NULL);
	if (!ADBG_EXPECT_CK_OK(c, rv))
		return;

	rv = C_Initialize(NULL);
	ADBG_EXPECT_CK_RESULT(c, CKR_CRYPTOKI_ALREADY_INITIALIZED, rv);

	rv = C_Finalize(NULL);
	ADBG_EXPECT_CK_OK(c, rv);
}

static void xtest_tee_test_4102(ADBG_Case_t *c)
{
	CK_RV rv;
	CK_SLOT_ID_PTR slot_ids = NULL;
	CK_ULONG slot_count;
	CK_ULONG slot_count2;
	CK_INFO lib_info;
	CK_SLOT_INFO slot_info;
	CK_TOKEN_INFO token_info;
	CK_FUNCTION_LIST_PTR ckfunc_list;
	size_t i;
	size_t j;
	CK_MECHANISM_TYPE_PTR mecha_types = NULL;

	rv = C_Initialize(NULL);
	if (!ADBG_EXPECT_CK_OK(c, rv))
		return;

	rv = C_GetInfo(&lib_info);
	if (!ADBG_EXPECT_CK_OK(c, rv))
		goto out;

	rv = C_GetFunctionList(&ckfunc_list);
	if (!ADBG_EXPECT_CK_OK(c, rv))
		goto out;

	slot_count2 = 0;
	rv = C_GetSlotList(0, NULL, &slot_count2);
	if (!ADBG_EXPECT_CK_OK(c, rv))
		goto out;

	slot_count = 0;

	rv = C_GetSlotList(1, NULL, &slot_count);
	if (!ADBG_EXPECT_CK_OK(c, rv))
		goto out;

	slot_ids = calloc(slot_count, sizeof(CK_SLOT_ID));
	if (!ADBG_EXPECT_TRUE(c, !slot_count || slot_ids))
		goto out;

	rv = C_GetSlotList(1, slot_ids, &slot_count);
	if (!ADBG_EXPECT_CK_OK(c, rv))
		goto out;

	for (i = 0; i < slot_count; i++) {
		CK_SLOT_ID slot = *(slot_ids + i);
		CK_ULONG mecha_count;

		rv = C_GetSlotInfo(slot, &slot_info);
		if (!ADBG_EXPECT_CK_OK(c, rv))
			goto out;

		rv = C_GetTokenInfo(slot, &token_info);
		if (!ADBG_EXPECT_CK_OK(c, rv))
			goto out;

		mecha_count = 0;
		rv = C_GetMechanismList(slot, NULL, &mecha_count);
		if (!ADBG_EXPECT_CK_OK(c, rv))
			goto out;

		mecha_types = calloc(mecha_count, sizeof(CK_MECHANISM_TYPE));
		if (!ADBG_EXPECT_TRUE(c, !mecha_count || mecha_types))
			goto out;

		rv = C_GetMechanismList(slot, mecha_types, &mecha_count);
		if (!ADBG_EXPECT_CK_OK(c, rv))
			goto out;

		if (level)
			Do_ADBG_Log("Token #%u mechanism capabilities:", i);

		for (j = 0; j < mecha_count; j++) {
			CK_MECHANISM_TYPE type = mecha_types[j];
			CK_MECHANISM_INFO mecha_info;
			size_t pos;
			size_t k;
			/* 1024byte should be enough, if not truncates  */
			char log[1024] = { 0 };

			rv = C_GetMechanismInfo(slot, type, &mecha_info);
			if (!ADBG_EXPECT_CK_OK(c, rv))
				goto out;

			/*  Verbose output on high levels */
			if (level == 0)
				continue;

			pos = snprintf(&log[0], sizeof(log),
					"%-30s Key size [%03lu %03lu]",
					ckm2str(type),
					mecha_info.ulMinKeySize,
					mecha_info.ulMaxKeySize);

			if (pos > sizeof(log)) {
				Do_ADBG_Log("| Error: internal short buffer");
				continue;
			}

			if (!mecha_info.flags) {
				Do_ADBG_Log("| %s\tAll flags down", &log[0]);
				continue;
			}

			if (pos < sizeof(log))
				pos += snprintf(&log[pos], sizeof(log) - pos,
						"\tFlags: ");

			for (k = 0; k < 32; k++) {
				if (!(mecha_info.flags & (1UL << k)) ||
				    pos >= sizeof(log))
					continue;

				pos += snprintf(&log[pos], sizeof(log) - pos,
						"%s ",
						ck_mecha_flag2str(1UL << k));
			}
			Do_ADBG_Log("| %s", &log[0]);
		}

		if (level)
			Do_ADBG_Log("`--- end token mechanism capabilities");

		free(mecha_types);
		mecha_types = NULL;
	}

out:
	free(slot_ids);
	free(mecha_types);

	rv = C_Finalize(NULL);
	ADBG_EXPECT_CK_OK(c, rv);
}

static void xtest_tee_test_4103(ADBG_Case_t *c)
{
	CK_RV rv;
	CK_SLOT_ID slot;
	CK_SESSION_HANDLE session[3];
	CK_FLAGS session_flags = CKF_SERIAL_SESSION | CKF_RW_SESSION;

	rv = init_lib_and_find_token_slot(&slot);
	if (!ADBG_EXPECT_CK_OK(c, rv))
		return;

	/* Open 3 sessions */
	rv = C_OpenSession(slot, session_flags, NULL, 0, &session[0]);
	if (!ADBG_EXPECT_CK_OK(c, rv))
		goto bail;

	rv = C_OpenSession(slot, session_flags, NULL, 0, &session[1]);
	if (!ADBG_EXPECT_CK_OK(c, rv))
		goto bail;

	rv = C_OpenSession(slot, session_flags, NULL, 0, &session[2]);
	if (!ADBG_EXPECT_CK_OK(c, rv))
		goto bail;

	/* Close 2 of them */
	rv = C_CloseSession(session[0]);
	if (!ADBG_EXPECT_CK_OK(c, rv))
		goto bail;

	rv = C_CloseSession(session[1]);
	if (!ADBG_EXPECT_CK_OK(c, rv))
		goto bail;

	/* Close all remaining sessions */
	rv = C_CloseAllSessions(slot);
	if (!ADBG_EXPECT_CK_OK(c, rv))
		goto bail;

	/* Should failed to close non existing session */
	rv = C_CloseSession(session[2]);
	if (!ADBG_EXPECT_COMPARE_UNSIGNED(c, rv, !=, CKR_OK))
		goto bail;

	/* Open a session, should be closed from library closure */
	rv = C_OpenSession(slot, session_flags, NULL, 0, &session[0]);
	if (!ADBG_EXPECT_CK_OK(c, rv))
		goto bail;

bail:
	rv = close_lib();
	ADBG_EXPECT_CK_OK(c, rv);
}

static void xtest_tee_test_4104(ADBG_Case_t *c)
{
	CK_RV rv;
	CK_SLOT_ID slot;
	CK_TOKEN_INFO token_info;
	char label32[32];
	/* Same content as test_token_so_pin[] but 1 more byte */
	char pin1[] = { 0, 1, 2, 3, 0, 5, 6, 7, 8, 9, 10 };
	/* Same content as test_token_so_pin[] but 1 different byte */
	char pin2[] = { 0, 1, 2, 3, 4, 5, 6, 0, 8 };
	CK_SESSION_HANDLE session = CK_INVALID_HANDLE;
	CK_FLAGS session_flags = CKF_SERIAL_SESSION | CKF_RW_SESSION;

	rv = init_lib_and_find_token_slot(&slot);
	if (!ADBG_EXPECT_CK_OK(c, rv))
		return;

	rv = C_GetTokenInfo(slot, &token_info);
	if (!ADBG_EXPECT_CK_OK(c, rv))
		goto bail;

	memcpy(label32, test_token_label, sizeof(label32));

	if (token_info.flags & CKF_TOKEN_INITIALIZED) {

		Do_ADBG_BeginSubCase(c, "Init already initialized token");

		// "Token is already initialized.\n"
		// TODO: skip this if token is about to lock

		rv = C_InitToken(slot, (CK_UTF8CHAR_PTR)test_token_so_pin,
				sizeof(test_token_so_pin) - 1,
				 (CK_UTF8CHAR_PTR)label32);
		if (!ADBG_EXPECT_COMPARE_UNSIGNED(c, rv, !=, CKR_OK))
			goto bail;

		rv = C_InitToken(slot, (CK_UTF8CHAR_PTR)pin1, sizeof(pin1),
				 (CK_UTF8CHAR_PTR)label32);
		if (!ADBG_EXPECT_COMPARE_UNSIGNED(c, rv, !=, CKR_OK))
			goto bail;


		rv = C_InitToken(slot, (CK_UTF8CHAR_PTR)pin2, sizeof(pin2),
				 (CK_UTF8CHAR_PTR)label32);
		if (!ADBG_EXPECT_COMPARE_UNSIGNED(c, rv, !=, CKR_OK))
			goto bail;

		rv = C_GetTokenInfo(slot, &token_info);
		if (!ADBG_EXPECT_CK_OK(c, rv))
			goto bail;

		/* Token should have set CKF_SO_PIN_COUNT_LOW to 1 */
		if (!ADBG_EXPECT_TRUE(c, !!(token_info.flags &
						CKF_SO_PIN_COUNT_LOW))) {
			rv = CKR_GENERAL_ERROR;
			goto bail;
		}

		rv = init_test_token(slot);
		if (!ADBG_EXPECT_CK_OK(c, rv))
			goto bail;

		rv = C_GetTokenInfo(slot, &token_info);
		if (!ADBG_EXPECT_CK_OK(c, rv))
			goto bail;

		/*
		 * Token should have reset CKF_SO_PIN_COUNT_LOW to 0.
		 * Other flags should show a sane initialized state.
		 */
		if (!ADBG_EXPECT_TRUE(c, !(token_info.flags &
						CKF_SO_PIN_COUNT_LOW)) ||
		    !ADBG_EXPECT_TRUE(c, !!(token_info.flags &
						CKF_TOKEN_INITIALIZED)) ||
		    !ADBG_EXPECT_TRUE(c, !(token_info.flags &
						CKF_ERROR_STATE)) ||
		    !ADBG_EXPECT_TRUE(c, !(token_info.flags &
						CKF_USER_PIN_INITIALIZED))) {
			rv = CKR_GENERAL_ERROR;
			goto bail;
		}

		rv = init_user_test_token(slot);
		if (!ADBG_EXPECT_CK_OK(c, rv))
			goto bail;

		rv = C_GetTokenInfo(slot, &token_info);
		if (!ADBG_EXPECT_CK_OK(c, rv))
			goto bail;

		if (!ADBG_EXPECT_TRUE(c, !(token_info.flags &
						CKF_USER_PIN_COUNT_LOW)) ||
		    !ADBG_EXPECT_TRUE(c, !(token_info.flags &
						CKF_USER_PIN_FINAL_TRY)) ||
		    !ADBG_EXPECT_TRUE(c, !(token_info.flags &
						CKF_USER_PIN_LOCKED)) ||
		    !ADBG_EXPECT_TRUE(c, !(token_info.flags &
						CKF_USER_PIN_TO_BE_CHANGED)) ||
		    !ADBG_EXPECT_TRUE(c, !!(token_info.flags &
						CKF_USER_PIN_INITIALIZED)) ||
		    !ADBG_EXPECT_TRUE(c, !(token_info.flags &
						CKF_ERROR_STATE))) {
			rv = CKR_GENERAL_ERROR;
			goto bail;
		}

	} else {
		//("Token was not yet initialized.\n");
		/*  We must provision the SO PIN */

		Do_ADBG_BeginSubCase(c, "Init brand new token");

		rv = init_test_token(slot);
		if (!ADBG_EXPECT_CK_OK(c, rv))
			goto bail;

		rv = C_GetTokenInfo(slot, &token_info);
		if (!ADBG_EXPECT_CK_OK(c, rv))
			goto bail;

		if (!ADBG_EXPECT_TRUE(c, !!(token_info.flags &
						CKF_TOKEN_INITIALIZED)) ||
		    !ADBG_EXPECT_TRUE(c, !(token_info.flags &
						CKF_ERROR_STATE)) ||
		    !ADBG_EXPECT_TRUE(c, !(token_info.flags &
						CKF_USER_PIN_INITIALIZED))) {
			rv = CKR_GENERAL_ERROR;
			goto bail;
		}

		rv = init_user_test_token(slot);
		if (!ADBG_EXPECT_CK_OK(c, rv))
			goto bail;

		rv = C_GetTokenInfo(slot, &token_info);
		if (!ADBG_EXPECT_CK_OK(c, rv))
			goto bail;

		if (!ADBG_EXPECT_TRUE(c, !!(token_info.flags &
						CKF_TOKEN_INITIALIZED)) ||
		    !ADBG_EXPECT_TRUE(c, !(token_info.flags &
						CKF_USER_PIN_COUNT_LOW)) ||
		    !ADBG_EXPECT_TRUE(c, !(token_info.flags &
						CKF_USER_PIN_FINAL_TRY)) ||
		    !ADBG_EXPECT_TRUE(c, !(token_info.flags &
						CKF_USER_PIN_LOCKED)) ||
		    !ADBG_EXPECT_TRUE(c, !(token_info.flags &
						CKF_USER_PIN_TO_BE_CHANGED)) ||
		    !ADBG_EXPECT_TRUE(c, !!(token_info.flags &
						CKF_USER_PIN_INITIALIZED)) ||
		    !ADBG_EXPECT_TRUE(c, !(token_info.flags &
						CKF_ERROR_STATE))) {
			rv = CKR_GENERAL_ERROR;
			goto bail;
		}
	}

	rv = close_lib();
	ADBG_EXPECT_CK_OK(c, rv);

	Do_ADBG_EndSubCase(c, NULL);

	/* Test login support */
	rv = init_lib_and_find_token_slot(&slot);
	if (!ADBG_EXPECT_CK_OK(c, rv))
		return;

	Do_ADBG_BeginSubCase(c, "Valid and invalid login/logout tests");

	rv = C_OpenSession(slot, session_flags, NULL, 0, &session);
	if (!ADBG_EXPECT_CK_OK(c, rv))
		goto bail;

	/* Logout: should fail as we did not log in yet */
	rv = logout_test_token(session);
	ADBG_EXPECT_COMPARE_UNSIGNED(c, rv, ==, CKR_USER_NOT_LOGGED_IN);

	/* Login/re-log/logout user */
	rv = login_user_test_token(session);
	if (!ADBG_EXPECT_CK_OK(c, rv))
		goto bail;

	rv = login_user_test_token(session);
	ADBG_EXPECT_COMPARE_UNSIGNED(c, rv, ==, CKR_USER_ALREADY_LOGGED_IN);

	rv = logout_test_token(session);
	if (!ADBG_EXPECT_CK_OK(c, rv))
		goto bail;

	/* Login/re-log/logout security officer */
	rv = login_so_test_token(session);
	if (!ADBG_EXPECT_CK_OK(c, rv))
		goto bail;

	rv = login_so_test_token(session);
	ADBG_EXPECT_COMPARE_UNSIGNED(c, rv, ==, CKR_USER_ALREADY_LOGGED_IN);

	rv = logout_test_token(session);
	if (!ADBG_EXPECT_CK_OK(c, rv))
		goto bail;

	/* Login user then so and reverse */
	rv = login_so_test_token(session);
	ADBG_EXPECT_CK_OK(c, rv);

	rv = login_user_test_token(session);
	ADBG_EXPECT_COMPARE_UNSIGNED(c, rv, ==,
					CKR_USER_ANOTHER_ALREADY_LOGGED_IN);

	rv = logout_test_token(session);
	if (!ADBG_EXPECT_CK_OK(c, rv))
		goto bail;

	rv = login_user_test_token(session);
	ADBG_EXPECT_CK_OK(c, rv);

	rv = login_so_test_token(session);
	ADBG_EXPECT_COMPARE_UNSIGNED(c, rv, ==,
					CKR_USER_ANOTHER_ALREADY_LOGGED_IN);

	rv = logout_test_token(session);
	ADBG_EXPECT_CK_OK(c, rv);

	/* Login context specifc, in an invalid case (need an operation) */
	rv = login_context_test_token(session);
	ADBG_EXPECT_COMPARE_UNSIGNED(c, rv, ==, CKR_OPERATION_NOT_INITIALIZED);

	/* TODO: login user, set pin, logout login old/new pin, restore PIN */

	/* TODO: login SO, set pin, logout login old/new pin, restore PIN */

	/* TODO: set pin (not logged), login old/new pin, restore PIN */

	rv = C_CloseSession(session);
	ADBG_EXPECT_CK_OK(c, rv);

bail:
	Do_ADBG_EndSubCase(c, NULL);

	rv = close_lib();
	ADBG_EXPECT_CK_OK(c, rv);
}

/* Bad key type */
static CK_ATTRIBUTE cktest_generate_gensecret_object_error1[] = {
	{ CKA_CLASS, &(CK_OBJECT_CLASS){CKO_SECRET_KEY},
						sizeof(CK_OBJECT_CLASS) },
	{ CKA_KEY_TYPE, &(CK_KEY_TYPE){CKK_AES}, sizeof(CK_KEY_TYPE) },
	{ CKA_ENCRYPT, &(CK_BBOOL){CK_TRUE}, sizeof(CK_BBOOL) },
	{ CKA_VALUE_LEN, &(CK_ULONG){16}, sizeof(CK_ULONG) },
};

/* Missing VALUE_LEN */
static CK_ATTRIBUTE cktest_generate_gensecret_object_error2[] = {
	{ CKA_CLASS, &(CK_OBJECT_CLASS){CKO_SECRET_KEY},
						sizeof(CK_OBJECT_CLASS) },
	{ CKA_KEY_TYPE, &(CK_KEY_TYPE){CKK_GENERIC_SECRET},
						sizeof(CK_KEY_TYPE) },
	{ CKA_ENCRYPT, &(CK_BBOOL){CK_TRUE}, sizeof(CK_BBOOL) },
};

/* Bad object class */
static CK_ATTRIBUTE cktest_generate_gensecret_object_error3[] = {
	{ CKA_CLASS, &(CK_OBJECT_CLASS){CKO_DATA}, sizeof(CK_OBJECT_CLASS) },
	{ CKA_KEY_TYPE, &(CK_KEY_TYPE){CKK_GENERIC_SECRET},
						sizeof(CK_KEY_TYPE) },
	{ CKA_ENCRYPT, &(CK_BBOOL){CK_TRUE}, sizeof(CK_BBOOL) },
	{ CKA_VALUE_LEN, &(CK_ULONG){16}, sizeof(CK_ULONG) },
};

/* Valid template to generate a generic secret */
static CK_ATTRIBUTE cktest_generate_gensecret_object[] = {
	{ CKA_CLASS, &(CK_OBJECT_CLASS){CKO_SECRET_KEY},
						sizeof(CK_OBJECT_CLASS) },
	{ CKA_KEY_TYPE, &(CK_KEY_TYPE){CKK_GENERIC_SECRET},
						sizeof(CK_KEY_TYPE) },
	{ CKA_ENCRYPT, &(CK_BBOOL){CK_TRUE}, sizeof(CK_BBOOL) },
	{ CKA_DECRYPT, &(CK_BBOOL){CK_TRUE}, sizeof(CK_BBOOL) },
	{ CKA_COPYABLE, &(CK_BBOOL){CK_TRUE}, sizeof(CK_BBOOL) },
	{ CKA_MODIFIABLE, &(CK_BBOOL){CK_TRUE}, sizeof(CK_BBOOL) },
	{ CKA_EXTRACTABLE, &(CK_BBOOL){CK_TRUE}, sizeof(CK_BBOOL) },
	{ CKA_VALUE_LEN, &(CK_ULONG){16}, sizeof(CK_ULONG) },
};

/* Valid template to generate an all AES purpose key */
static CK_ATTRIBUTE cktest_generate_aes_object[] = {
	{ CKA_CLASS, &(CK_OBJECT_CLASS){CKO_SECRET_KEY},
						sizeof(CK_OBJECT_CLASS) },
	{ CKA_KEY_TYPE, &(CK_KEY_TYPE){CKK_AES}, sizeof(CK_KEY_TYPE) },
	{ CKA_ENCRYPT, &(CK_BBOOL){CK_TRUE}, sizeof(CK_BBOOL) },
	{ CKA_DECRYPT, &(CK_BBOOL){CK_TRUE}, sizeof(CK_BBOOL) },
	{ CKA_COPYABLE, &(CK_BBOOL){CK_TRUE}, sizeof(CK_BBOOL) },
	{ CKA_MODIFIABLE, &(CK_BBOOL){CK_TRUE}, sizeof(CK_BBOOL) },
	{ CKA_EXTRACTABLE, &(CK_BBOOL){CK_TRUE}, sizeof(CK_BBOOL) },
	{ CKA_VALUE_LEN, &(CK_ULONG){16}, sizeof(CK_ULONG) },
};

/* Valid template to generate an ECC key pair */
static CK_ATTRIBUTE cktest_generate_ecc_pubkey[] = {
	{ CKA_CLASS, &(CK_OBJECT_CLASS){CKO_PUBLIC_KEY},
						sizeof(CK_OBJECT_CLASS) },
	{ CKA_KEY_TYPE, &(CK_KEY_TYPE){CKK_EC}, sizeof(CK_KEY_TYPE) },
	{ CKA_VERIFY, &(CK_BBOOL){CK_TRUE}, sizeof(CK_BBOOL) },
	{ CKA_ID, &(CK_ULONG){1}, sizeof(CK_ULONG) },
	{ CKA_EC_PARAMS, NULL, 0 },	/* Will be run at runtime */
	{ CKA_LABEL, NULL, 0 },		/* Will be run at runtime */
};
static CK_ATTRIBUTE cktest_generate_ecc_privkey[] = {
	{ CKA_CLASS, &(CK_OBJECT_CLASS){CKO_PRIVATE_KEY},
						sizeof(CK_OBJECT_CLASS) },
	{ CKA_KEY_TYPE, &(CK_KEY_TYPE){CKK_EC}, sizeof(CK_KEY_TYPE) },
	{ CKA_SIGN, &(CK_BBOOL){CK_TRUE}, sizeof(CK_BBOOL) },
	{ CKA_DERIVE, &(CK_BBOOL){CK_TRUE}, sizeof(CK_BBOOL) },
	{ CKA_ID, &(CK_ULONG){1}, sizeof(CK_ULONG) },
	{ CKA_EC_PARAMS, NULL, 0 },	/* Will be run at runtime */
	{ CKA_LABEL, NULL, 0 },		/* Will be run at runtime */
};

/* Valid template to generate an RSA key pair */
static CK_ATTRIBUTE cktest_generate_rsa_pubkey[] = {
	{ CKA_CLASS, &(CK_OBJECT_CLASS){CKO_PUBLIC_KEY},
						sizeof(CK_OBJECT_CLASS) },
	{ CKA_KEY_TYPE, &(CK_KEY_TYPE){CKK_RSA}, sizeof(CK_KEY_TYPE) },
	{ CKA_VERIFY, &(CK_BBOOL){CK_TRUE}, sizeof(CK_BBOOL) },
	{ CKA_ID, &(CK_ULONG){1}, sizeof(CK_ULONG) },
	{ CKA_MODULUS_BITS, NULL, 0 },	/* Will be run at runtime */
	{ CKA_LABEL, NULL, 0 },		/* Will be run at runtime */
};
static CK_ATTRIBUTE cktest_generate_rsa_privkey[] = {
	{ CKA_CLASS, &(CK_OBJECT_CLASS){CKO_PRIVATE_KEY},
						sizeof(CK_OBJECT_CLASS) },
	{ CKA_KEY_TYPE, &(CK_KEY_TYPE){CKK_RSA}, sizeof(CK_KEY_TYPE) },
	{ CKA_SIGN, &(CK_BBOOL){CK_TRUE}, sizeof(CK_BBOOL) },
	{ CKA_DERIVE, &(CK_BBOOL){CK_TRUE}, sizeof(CK_BBOOL) },
	{ CKA_ID, &(CK_ULONG){1}, sizeof(CK_ULONG) },
	{ CKA_LABEL, NULL, 0 },		/* Will be run at runtime */
};

/*
 * DER encoding of elliptic curves supported by the
 * GPD TEE Core Internal API v1.2
 */
static uint8_t __unused nist_secp192r1_der[] = {
	0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x01
};
static uint8_t __unused nist_secp224r1_der[] = {
	0x06, 0x05, 0x2b, 0x81, 0x04, 0x00, 0x21
};
static uint8_t __unused nist_secp256r1_der[] = {
	0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07
};
static uint8_t __unused nist_secp384r1_der[] = {
	0x06, 0x05, 0x2b, 0x81, 0x04, 0x00, 0x22
};
static uint8_t __unused nist_secp521r1_der[] = {
	0x06, 0x05, 0x2b, 0x81, 0x04, 0x00, 0x23
};

struct ecc_params {
	const char *info;
	uint8_t *der;
	size_t der_size;
	CK_MECHANISM_TYPE test_mecha;
};
#define ECC_PARAMS(_str, _der, _mecha) {	\
		.info = (_str),			\
		.der = (_der),			\
		.der_size = sizeof(_der),	\
		.test_mecha = _mecha,		\
	}

static struct ecc_params ecc_params_der[] = {
	ECC_PARAMS("NIST SECP192R1", nist_secp192r1_der, CKM_ECDSA),
	//ECC_PARAMS("NIST SECP224R1", nist_secp224r1_der, CKM_ECDSA),
	//ECC_PARAMS("NIST SECP256R1", nist_secp256r1_der, CKM_ECDSA),
	//ECC_PARAMS("NIST SECP384R1", nist_secp384r1_der, CKM_ECDSA),
	//ECC_PARAMS("NIST SECP521R1", nist_secp521r1_der, CKM_ECDSA),
};

static int set_ck_attr(CK_ATTRIBUTE *attrs, size_t count, CK_ULONG id,
			CK_VOID_PTR *data, CK_ULONG size)
{
	size_t idx;

	for (idx = 0; idx < count; idx++) {
		if (attrs[idx].type != id)
			continue;

		if (attrs[idx].pValue && attrs[idx].ulValueLen == size) {
			memcpy(attrs[idx].pValue, data, size);
		} else {
			attrs[idx].pValue = data;
			attrs[idx].ulValueLen = size;
		}
		return 0;
	}

	return 1;
}

static int clear_ck_attr(CK_ATTRIBUTE *attrs, size_t count, CK_ULONG id)
{
	size_t idx;

	for (idx = 0; idx < count; idx++) {
		if (attrs[idx].type != id)
			continue;

		attrs[idx].pValue = NULL;
		attrs[idx].ulValueLen = 0;
		return 0;
	}

	return 1;
}

#define SET_CK_ATTR(attrs, id, data, size) \
	set_ck_attr((CK_ATTRIBUTE *)attrs, ARRAY_SIZE(attrs), id, \
			(CK_VOID_PTR)data, (CK_ULONG)size)

#define CLEAR_CK_ATTR(attrs, id) \
	clear_ck_attr((CK_ATTRIBUTE *)attrs, ARRAY_SIZE(attrs), id)

/* Generate a generic secret */
static void xtest_tee_test_4105(ADBG_Case_t *c)
{
	CK_RV rv;
	CK_SLOT_ID slot;
	CK_SESSION_HANDLE session = CK_INVALID_HANDLE;
	CK_OBJECT_HANDLE obj_hdl;
	CK_OBJECT_HANDLE obj_hdl2;
	CK_FLAGS session_flags = CKF_SERIAL_SESSION | CKF_RW_SESSION;
	size_t idx;
	int subcase = 0;
	CK_MECHANISM test_mecha = { 0 };
	CK_ULONG ck_ul;

	rv = init_lib_and_find_token_slot(&slot);
	if (!ADBG_EXPECT_CK_OK(c, rv))
		return;

	rv = init_user_test_token(slot);
	if (!ADBG_EXPECT_CK_OK(c, rv)) {
		close_lib();
		return;
	}

	rv = C_OpenSession(slot, session_flags, NULL, 0, &session);
	if (!ADBG_EXPECT_CK_OK(c, rv)) {
		close_lib();
		return;
	}

	/*
	 * Generate a Generic Secret object.
	 * Try to encrpyt with, it should fail...
	 */
	Do_ADBG_BeginSubCase(c, "Generate generic secret and do AES with");
	subcase = 1;

	memset(&test_mecha, 0, sizeof(test_mecha));
	test_mecha.mechanism = CKM_GENERIC_SECRET_KEY_GEN;

	rv = C_GenerateKey(session, &test_mecha,
			   cktest_generate_gensecret_object,
			   ARRAY_SIZE(cktest_generate_gensecret_object),
			   &obj_hdl);
	if (!ADBG_EXPECT_CK_OK(c, rv))
		goto bail;

	rv = C_EncryptInit(session, &cktest_aes_cbc_mechanism, obj_hdl);
	if (!ADBG_EXPECT_CK_RESULT(c, rv, CKR_KEY_FUNCTION_NOT_PERMITTED))
		goto bail;

	rv = C_DestroyObject(session, obj_hdl);
	if (!ADBG_EXPECT_CK_OK(c, rv))
		goto bail;

	Do_ADBG_EndSubCase(c, NULL);
	subcase = 0;

	/*
	 * Generate Generic Secret objects using invalid templates
	 */
	Do_ADBG_BeginSubCase(c, "Generate invalid generic secrets");
	subcase = 1;

	memset(&test_mecha, 0, sizeof(test_mecha));
	test_mecha.mechanism = CKM_GENERIC_SECRET_KEY_GEN;

	rv = C_GenerateKey(session, &test_mecha,
			   cktest_generate_gensecret_object_error1,
			   ARRAY_SIZE(cktest_generate_gensecret_object_error1),
			   &obj_hdl);
	if (!ADBG_EXPECT_COMPARE_UNSIGNED(c, rv, !=, CKR_OK))
		goto bail;

	rv = C_GenerateKey(session, &test_mecha,
			   cktest_generate_gensecret_object_error2,
			   ARRAY_SIZE(cktest_generate_gensecret_object_error2),
			   &obj_hdl);
	if (!ADBG_EXPECT_COMPARE_UNSIGNED(c, rv, !=, CKR_OK))
		goto bail;

	rv = C_GenerateKey(session, &test_mecha,
			   cktest_generate_gensecret_object_error3,
			   ARRAY_SIZE(cktest_generate_gensecret_object_error3),
			   &obj_hdl);
	if (!ADBG_EXPECT_COMPARE_UNSIGNED(c, rv, !=, CKR_OK))
		goto bail;

	Do_ADBG_EndSubCase(c, NULL);
	subcase = 0;

	/*
	 * Generate a 128bit AES symmetric key
	 * Try to encrypt with, it should succeed.
	 */
	Do_ADBG_BeginSubCase(c, "Generate AES secret key and encrypt with");
	subcase = 1;

	memset(&test_mecha, 0, sizeof(test_mecha));
	test_mecha.mechanism = CKM_AES_KEY_GEN;

	rv = C_GenerateKey(session, &test_mecha,
			   cktest_generate_aes_object,
			   ARRAY_SIZE(cktest_generate_aes_object),
			   &obj_hdl);
	if (!ADBG_EXPECT_CK_OK(c, rv))
		goto bail;


	rv = C_EncryptInit(session, &cktest_aes_cbc_mechanism, obj_hdl);
	if (!ADBG_EXPECT_CK_OK(c, rv))
		goto bail;

	/* Only check that the operation is no more active */
	rv = C_EncryptFinal(session, NULL, NULL);
	if (!ADBG_EXPECT_COMPARE_UNSIGNED(c, rv, !=, CKR_BUFFER_TOO_SMALL))
		goto bail;

	rv = C_DestroyObject(session, obj_hdl);
	if (!ADBG_EXPECT_CK_OK(c, rv))
		goto bail;

	Do_ADBG_EndSubCase(c, NULL);
	subcase = 0;

	/*
	 * Generate a ECDSA asymmetric key
	 * Try to sign/verify with, it should succeed.
	 */

	rv = login_user_test_token(session);
	if (!ADBG_EXPECT_CK_OK(c, rv))
		goto bail;

	for (idx = 0; idx < ARRAY_SIZE(ecc_params_der); idx++) {
		if (subcase)
			Do_ADBG_EndSubCase(c, NULL);

		Do_ADBG_BeginSubCase(c, "Generate ECC key pair %s",
					ecc_params_der[idx].info);
		subcase = 1;

		if (SET_CK_ATTR(cktest_generate_ecc_pubkey, CKA_EC_PARAMS,
				ecc_params_der[idx].der,
				ecc_params_der[idx].der_size) ||
		    SET_CK_ATTR(cktest_generate_ecc_pubkey, CKA_LABEL,
				ecc_params_der[idx].info,
				strlen(ecc_params_der[idx].info) - 1) ||
		    SET_CK_ATTR(cktest_generate_ecc_privkey, CKA_EC_PARAMS,
				ecc_params_der[idx].der,
				ecc_params_der[idx].der_size) ||
		    SET_CK_ATTR(cktest_generate_ecc_privkey, CKA_LABEL,
				ecc_params_der[idx].info,
				strlen(ecc_params_der[idx].info) - 1)) {
			ADBG_EXPECT_TRUE(c, false);
			continue;
		}

		memset(&test_mecha, 0, sizeof(test_mecha));
		test_mecha.mechanism = CKM_EC_KEY_PAIR_GEN;

		rv = C_GenerateKeyPair(session, &test_mecha,
			   cktest_generate_ecc_pubkey,
			   ARRAY_SIZE(cktest_generate_ecc_pubkey),
			   cktest_generate_ecc_privkey,
			   ARRAY_SIZE(cktest_generate_ecc_privkey),
			   &obj_hdl, &obj_hdl2);

		/* Clear temporary references for next test to find its way */
		if (CLEAR_CK_ATTR(cktest_generate_ecc_pubkey, CKA_EC_PARAMS) ||
		    CLEAR_CK_ATTR(cktest_generate_ecc_pubkey, CKA_LABEL) ||
		    CLEAR_CK_ATTR(cktest_generate_ecc_privkey, CKA_EC_PARAMS) ||
		    CLEAR_CK_ATTR(cktest_generate_ecc_privkey, CKA_LABEL)) {
			ADBG_EXPECT_TRUE(c, false);
			continue;
		}

		if (!ADBG_EXPECT_CK_OK(c, rv))
			continue;

		test_mecha.mechanism = ecc_params_der[idx].test_mecha;

		rv = C_SignInit(session, &test_mecha, obj_hdl2);
		if (ADBG_EXPECT_CK_OK(c, rv)) {
			/* Only check that the operation is no more active */
			rv = C_SignFinal(session, NULL, NULL);
			ADBG_EXPECT_COMPARE_UNSIGNED(c, rv, !=,
							CKR_BUFFER_TOO_SMALL);
		}

		rv = C_VerifyInit(session, &test_mecha, obj_hdl);
		if (ADBG_EXPECT_CK_OK(c, rv)) {
			/* Only check that the operation is no more active */
			rv = C_VerifyFinal(session, NULL, 0);
			ADBG_EXPECT_COMPARE_UNSIGNED(c, rv, !=,
							CKR_BUFFER_TOO_SMALL);
		}

		rv = C_DestroyObject(session, obj_hdl);
		ADBG_EXPECT_CK_OK(c, rv);

		rv = C_DestroyObject(session, obj_hdl2);
		ADBG_EXPECT_CK_OK(c, rv);
	}

	rv = logout_test_token(session);
	ADBG_EXPECT_CK_OK(c, rv);

	if (subcase)
		Do_ADBG_EndSubCase(c, NULL);


	/*
	 * Generate a RSA asymmetric key
	 * Try to sign/verify with, it should succeed.
	 */
	ck_ul = 512;

	rv = login_user_test_token(session);
	if (!ADBG_EXPECT_CK_OK(c, rv))
		goto bail;

	Do_ADBG_BeginSubCase(c, "Generate %lu bit RSA key pair", ck_ul);
	subcase = 1;

	if (SET_CK_ATTR(cktest_generate_rsa_pubkey, CKA_MODULUS_BITS,
			&ck_ul, sizeof(CK_ULONG))) {
			ADBG_EXPECT_TRUE(c, false);
			goto bail;
	}

	memset(&test_mecha, 0, sizeof(test_mecha));
	test_mecha.mechanism = CKM_RSA_PKCS_KEY_PAIR_GEN;

	rv = C_GenerateKeyPair(session, &test_mecha,
		   cktest_generate_rsa_pubkey,
		   ARRAY_SIZE(cktest_generate_rsa_pubkey),
		   cktest_generate_rsa_privkey,
		   ARRAY_SIZE(cktest_generate_rsa_privkey),
		   &obj_hdl, &obj_hdl2);

	if (!ADBG_EXPECT_CK_OK(c, rv))
		goto bail;

	memset(&test_mecha, 0, sizeof(test_mecha));
	test_mecha.mechanism = CKM_SHA1_RSA_PKCS;

	rv = C_SignInit(session, &test_mecha, obj_hdl2);
	if (ADBG_EXPECT_CK_OK(c, rv)) {
		/* Only check that the operation is no more active */
		rv = C_SignFinal(session, NULL, NULL);
		ADBG_EXPECT_COMPARE_UNSIGNED(c, rv, !=, CKR_BUFFER_TOO_SMALL);
	}

	rv = C_VerifyInit(session, &test_mecha, obj_hdl);
	if (ADBG_EXPECT_CK_OK(c, rv)) {
		/* Only check that the operation is no more active */
		rv = C_VerifyFinal(session, NULL, 0);
		ADBG_EXPECT_COMPARE_UNSIGNED(c, rv, !=, CKR_BUFFER_TOO_SMALL);
	}

	rv = C_DestroyObject(session, obj_hdl);
	ADBG_EXPECT_CK_OK(c, rv);

	rv = C_DestroyObject(session, obj_hdl2);
	ADBG_EXPECT_CK_OK(c, rv);

	rv = logout_test_token(session);
	ADBG_EXPECT_CK_OK(c, rv);

bail:
	if (subcase)
		Do_ADBG_EndSubCase(c, NULL);

	rv = C_CloseSession(session);
	ADBG_EXPECT_CK_OK(c, rv);

	rv = close_lib();
	ADBG_EXPECT_CK_OK(c, rv);
}

static CK_ATTRIBUTE cktest_token_object[] = {
	{ CKA_DECRYPT,	&(CK_BBOOL){CK_TRUE}, sizeof(CK_BBOOL) },
	{ CKA_TOKEN,	&(CK_BBOOL){CK_TRUE}, sizeof(CK_BBOOL) },
	{ CKA_MODIFIABLE, &(CK_BBOOL){CK_TRUE}, sizeof(CK_BBOOL) },
	{ CKA_CLASS,	&(CK_OBJECT_CLASS){CKO_SECRET_KEY},
						sizeof(CK_OBJECT_CLASS) },
	{ CKA_KEY_TYPE,	&(CK_KEY_TYPE){CKK_AES}, sizeof(CK_KEY_TYPE) },
	{ CKA_VALUE,	(void *)cktest_aes128_key, sizeof(cktest_aes128_key) },
};

static CK_ATTRIBUTE cktest_session_object[] = {
	{ CKA_DECRYPT,	&(CK_BBOOL){CK_TRUE}, sizeof(CK_BBOOL) },
	{ CKA_TOKEN,	&(CK_BBOOL){CK_FALSE}, sizeof(CK_BBOOL) },
	{ CKA_MODIFIABLE, &(CK_BBOOL){CK_TRUE}, sizeof(CK_BBOOL) },
	{ CKA_KEY_TYPE,	&(CK_KEY_TYPE){CKK_AES}, sizeof(CK_KEY_TYPE) },
	{ CKA_CLASS,	&(CK_OBJECT_CLASS){CKO_SECRET_KEY},
						sizeof(CK_OBJECT_CLASS) },
	{ CKA_VALUE,	(void *)cktest_aes128_key, sizeof(cktest_aes128_key) },
};

/* Create session object and token object from a session */
static void test_create_destroy_single_object(ADBG_Case_t *c, int persistent)
{
	CK_RV rv;
	CK_SLOT_ID slot;
	CK_SESSION_HANDLE session = CK_INVALID_HANDLE;
	CK_OBJECT_HANDLE obj_hdl;
	CK_FLAGS session_flags = CKF_SERIAL_SESSION | CKF_RW_SESSION;

	rv = init_lib_and_find_token_slot(&slot);
	if (!ADBG_EXPECT_CK_OK(c, rv))
		return;

	rv = C_OpenSession(slot, session_flags, NULL, 0, &session);
	if (!ADBG_EXPECT_CK_OK(c, rv))
		goto bail;

	if (persistent)
		rv = C_CreateObject(session, cktest_token_object,
				    ARRAY_SIZE(cktest_token_object),
				    &obj_hdl);
	else
		rv = C_CreateObject(session, cktest_session_object,
				    ARRAY_SIZE(cktest_session_object),
				    &obj_hdl);

	if (!ADBG_EXPECT_CK_OK(c, rv))
		goto bail;

	rv = C_DestroyObject(session, obj_hdl);
	if (!ADBG_EXPECT_CK_OK(c, rv))
		goto bail;

bail:
	rv = C_CloseSession(session);
	ADBG_EXPECT_CK_OK(c, rv);

	rv = close_lib();
	ADBG_EXPECT_CK_OK(c, rv);
}

static void test_create_destroy_session_objects(ADBG_Case_t *c)
{
	CK_RV rv;
	CK_SLOT_ID slot;
	CK_SESSION_HANDLE session = CK_INVALID_HANDLE;
	CK_OBJECT_HANDLE obj_hdl[512];
	CK_FLAGS session_flags = CKF_SERIAL_SESSION | CKF_RW_SESSION;
	size_t n;

	rv = init_lib_and_find_token_slot(&slot);
	if (!ADBG_EXPECT_CK_OK(c, rv))
		return;

	rv = C_OpenSession(slot, session_flags, NULL, 0, &session);
	if (!ADBG_EXPECT_CK_OK(c, rv))
		goto bail;

	for (n = 0; n < ARRAY_SIZE(obj_hdl); n++) {
		rv = C_CreateObject(session, cktest_session_object,
				    ARRAY_SIZE(cktest_session_object),
				    obj_hdl + n);

		if (rv == CKR_DEVICE_MEMORY)
			break;

		if (!ADBG_EXPECT_CK_OK(c, rv)) {
			n--;
			break;
		}
	}

	Do_ADBG_Log("    created object count: %zu", n);

	rv = C_CloseSession(session);
	ADBG_EXPECT_CK_OK(c, rv);

	rv = C_OpenSession(slot, session_flags, NULL, 0, &session);
	if (!ADBG_EXPECT_CK_OK(c, rv))
		goto bail;

	rv = C_CreateObject(session, cktest_session_object,
			    ARRAY_SIZE(cktest_session_object),
			    obj_hdl);

	if (!ADBG_EXPECT_CK_OK(c, rv))
		goto bail;

bail:
	rv = C_CloseSession(session);
	ADBG_EXPECT_CK_OK(c, rv);

	rv = close_lib();
	ADBG_EXPECT_CK_OK(c, rv);
}

static void xtest_tee_test_4106(ADBG_Case_t *c)
{
	Do_ADBG_BeginSubCase(c, "Create and destroy a volatile object");
	test_create_destroy_single_object(c, 0);
	Do_ADBG_EndSubCase(c, NULL);

	Do_ADBG_BeginSubCase(c, "Create and destroy a persistent object");
	test_create_destroy_single_object(c, 1);
	Do_ADBG_EndSubCase(c, NULL);

	Do_ADBG_BeginSubCase(c, "Create and destroy a persistent object");
	test_create_destroy_session_objects(c);
	Do_ADBG_EndSubCase(c, NULL);
}

/* Create session object and token object from a session */
static void test_create_objects_in_session(ADBG_Case_t *c, int readwrite)
{
	CK_RV rv;
	CK_SLOT_ID slot;
	CK_SESSION_HANDLE session;
	CK_OBJECT_HANDLE token_obj_hld;
	CK_OBJECT_HANDLE session_obj_hld;
	CK_FLAGS session_flags = CKF_SERIAL_SESSION;

	rv = init_lib_and_find_token_slot(&slot);
	if (!ADBG_EXPECT_CK_OK(c, rv))
		return;

	if (readwrite)
		session_flags |= CKF_RW_SESSION;

	rv = C_OpenSession(slot, session_flags, NULL, 0, &session);
	if (!ADBG_EXPECT_CK_OK(c, rv))
		goto bail;

	rv = C_CreateObject(session, cktest_token_object,
			    ARRAY_SIZE(cktest_token_object),
			    &token_obj_hld);

	if (readwrite) {
		if (!ADBG_EXPECT_CK_OK(c, rv))
			goto bail;
	} else {
		if (!ADBG_EXPECT_CK_RESULT(c, rv, CKR_SESSION_READ_ONLY))
			goto bail;
	}

	rv = C_CreateObject(session, cktest_session_object,
			    ARRAY_SIZE(cktest_session_object),
			    &session_obj_hld);

	if (!ADBG_EXPECT_CK_OK(c, rv))
		goto bail;

	if (readwrite)
		rv = C_DestroyObject(session, token_obj_hld);

	if (!ADBG_EXPECT_CK_OK(c, rv))
		goto bail;

	rv = C_DestroyObject(session, session_obj_hld);
	ADBG_EXPECT_CK_OK(c, rv);

bail:
	rv = C_CloseSession(session);
	ADBG_EXPECT_CK_OK(c, rv);

	rv = close_lib();
	ADBG_EXPECT_CK_OK(c, rv);
}

static void xtest_tee_test_4107(ADBG_Case_t *c)
{
	Do_ADBG_BeginSubCase(c, "Create objects in a read-only session");
	test_create_objects_in_session(c, 0);
	Do_ADBG_EndSubCase(c, NULL);

	Do_ADBG_BeginSubCase(c, "Create objects in a read/write session");
	test_create_objects_in_session(c, 1);
	Do_ADBG_EndSubCase(c, NULL);
}

static const CK_MECHANISM_TYPE allowed_only_aes_ecb[] = {
	CKM_AES_ECB,
};
static const CK_MECHANISM_TYPE allowed_not_aes_ecb[] = {
	CKM_AES_CBC, CKM_AES_CBC_PAD, CKM_AES_CTR, CKM_AES_CTS,
	CKM_AES_GCM, CKM_AES_CCM,
};
static const CK_MECHANISM_TYPE allowed_only_aes_cbcnopad[] = {
	CKM_AES_CBC,
};
static const CK_MECHANISM_TYPE allowed_not_aes_cbcnopad[] = {
	CKM_AES_ECB, CKM_AES_CBC_PAD, CKM_AES_CTR, CKM_AES_CTS,
	CKM_AES_GCM, CKM_AES_CCM,
};
static const CK_MECHANISM_TYPE allowed_only_aes_ctr[] = {
	CKM_AES_CTR,
};
static const CK_MECHANISM_TYPE allowed_not_aes_ctr[] = {
	CKM_AES_ECB, CKM_AES_CBC, CKM_AES_CBC_PAD, CKM_AES_CTS,
	CKM_AES_GCM, CKM_AES_CCM,
};
static const CK_MECHANISM_TYPE allowed_only_aes_cts[] = {
	CKM_AES_CTS,
};
static const CK_MECHANISM_TYPE allowed_not_aes_cts[] = {
	CKM_AES_ECB, CKM_AES_CBC, CKM_AES_CBC_PAD, CKM_AES_CTR,
	CKM_AES_GCM, CKM_AES_CCM,
};

static const CK_MECHANISM_TYPE allowed_only_aes_ccm[] = {
	CKM_AES_CCM,
};
static const CK_MECHANISM_TYPE allowed_not_aes_ccm[] = {
	CKM_AES_ECB, CKM_AES_CBC, CKM_AES_CBC_PAD, CKM_AES_CTR,
	CKM_AES_CTS, CKM_AES_GCM,
};

static const CK_MECHANISM_TYPE allowed_only_aes_gcm[] = {
	CKM_AES_GCM,
};
static const CK_MECHANISM_TYPE allowed_not_aes_gcm[] = {
	CKM_AES_ECB, CKM_AES_CBC, CKM_AES_CBC_PAD, CKM_AES_CTR,
	CKM_AES_CTS, CKM_AES_CCM,
};

#define CKTEST_AES_KEY \
	{ CKA_CLASS,	&(CK_OBJECT_CLASS){CKO_SECRET_KEY},	\
			sizeof(CK_OBJECT_CLASS) },		\
	{ CKA_KEY_TYPE,	&(CK_KEY_TYPE){CKK_AES},		\
			sizeof(CK_KEY_TYPE) },			\
	{ CKA_VALUE,	(void *)cktest_aes128_key,		\
			sizeof(cktest_aes128_key) }

#define CKTEST_AES_ALLOWED_KEY(_allowed) \
	{ CKA_ALLOWED_MECHANISMS, (void *)_allowed, sizeof(_allowed), }

#define CK_KEY_ALLOWED_AES_TEST(_label, _allowed) \
	static CK_ATTRIBUTE _label[] = {				\
		CKTEST_AES_KEY,						\
		{ CKA_ENCRYPT,	&(CK_BBOOL){CK_TRUE}, sizeof(CK_BBOOL) }, \
		{ CKA_DECRYPT,	&(CK_BBOOL){CK_TRUE}, sizeof(CK_BBOOL) }, \
		CKTEST_AES_ALLOWED_KEY(_allowed),			\
	}

#define CK_KEY_ALLOWED_AES_ENC_TEST(_label, _allowed) \
	static CK_ATTRIBUTE _label[] = {				\
		CKTEST_AES_KEY,						\
		{ CKA_ENCRYPT,	&(CK_BBOOL){CK_TRUE}, sizeof(CK_BBOOL) }, \
		CKTEST_AES_ALLOWED_KEY(_allowed),			\
	}
#define CK_KEY_ALLOWED_AES_DEC_TEST(_label, _allowed) \
	static CK_ATTRIBUTE _label[] = {				\
		CKTEST_AES_KEY,						\
		{ CKA_DECRYPT,	&(CK_BBOOL){CK_TRUE}, sizeof(CK_BBOOL) }, \
		CKTEST_AES_ALLOWED_KEY(_allowed),			\
	}

CK_KEY_ALLOWED_AES_TEST(cktest_aes_only_ecb, allowed_only_aes_ecb);
CK_KEY_ALLOWED_AES_TEST(cktest_aes_not_ecb, allowed_not_aes_ecb);
CK_KEY_ALLOWED_AES_TEST(cktest_aes_only_cbcnopad, allowed_only_aes_cbcnopad);
CK_KEY_ALLOWED_AES_TEST(cktest_aes_not_cbcnopad, allowed_not_aes_cbcnopad);
CK_KEY_ALLOWED_AES_TEST(cktest_aes_only_cts, allowed_only_aes_cts);
CK_KEY_ALLOWED_AES_TEST(cktest_aes_not_cts, allowed_not_aes_cts);
CK_KEY_ALLOWED_AES_TEST(cktest_aes_only_ctr, allowed_only_aes_ctr);
CK_KEY_ALLOWED_AES_TEST(cktest_aes_not_ctr, allowed_not_aes_ctr);
CK_KEY_ALLOWED_AES_TEST(cktest_aes_only_ccm, allowed_only_aes_ccm);
CK_KEY_ALLOWED_AES_TEST(cktest_aes_not_ccm, allowed_not_aes_ccm);
CK_KEY_ALLOWED_AES_TEST(cktest_aes_only_gcm, allowed_only_aes_gcm);
CK_KEY_ALLOWED_AES_TEST(cktest_aes_not_gcm, allowed_not_aes_gcm);

struct cktest_allowed_test {
	CK_ATTRIBUTE_PTR attr_key;
	CK_ULONG attr_count;
	CK_MECHANISM_PTR mechanism;
};

#define CKTEST_KEY_MECHA(key, mecha) {	\
		.attr_key = key,		\
		.attr_count = ARRAY_SIZE(key),	\
		.mechanism = mecha,		\
	}

static const struct cktest_allowed_test cktest_allowed_valid[] = {
	CKTEST_KEY_MECHA(cktest_aes_only_ecb, &cktest_aes_ecb_mechanism),
	CKTEST_KEY_MECHA(cktest_aes_only_cbcnopad, &cktest_aes_cbc_mechanism),
	CKTEST_KEY_MECHA(cktest_aes_only_cts, &cktest_aes_cts_mechanism),
	CKTEST_KEY_MECHA(cktest_aes_only_ctr, &cktest_aes_ctr_mechanism),
	CKTEST_KEY_MECHA(cktest_aes_only_ccm, &cktest_aes_ccm_mechanism),
	CKTEST_KEY_MECHA(cktest_aes_only_gcm, &cktest_aes_gcm_mechanism),
};

static const struct cktest_allowed_test cktest_allowed_invalid[] = {
	CKTEST_KEY_MECHA(cktest_aes_not_ecb, &cktest_aes_ecb_mechanism),
	CKTEST_KEY_MECHA(cktest_aes_not_cbcnopad, &cktest_aes_cbc_mechanism),
	CKTEST_KEY_MECHA(cktest_aes_not_cts, &cktest_aes_cts_mechanism),
	CKTEST_KEY_MECHA(cktest_aes_not_ctr, &cktest_aes_ctr_mechanism),
	CKTEST_KEY_MECHA(cktest_aes_not_ccm, &cktest_aes_ccm_mechanism),
	CKTEST_KEY_MECHA(cktest_aes_not_gcm, &cktest_aes_gcm_mechanism),
};

/* Create session object and token object from a session */
static CK_RV cipher_init_final(ADBG_Case_t *c, CK_SESSION_HANDLE session,
				CK_ATTRIBUTE_PTR attr_key, CK_ULONG attr_count,
				CK_MECHANISM_PTR mechanism, uint32_t mode,
				CK_RV expected_rc)
{
	CK_RV rv;
	CK_OBJECT_HANDLE object;

	switch (mode) {
	case TEE_MODE_ENCRYPT:
	case TEE_MODE_DECRYPT:
		break;
	default:
		ADBG_EXPECT_TRUE(c, false);
	}

	rv = C_CreateObject(session, attr_key, attr_count, &object);
	if (!ADBG_EXPECT_CK_OK(c, rv))
		goto bail;

	if (mode == TEE_MODE_ENCRYPT)
		rv = C_EncryptInit(session, mechanism, object);
	if (mode == TEE_MODE_DECRYPT)
		rv = C_DecryptInit(session, mechanism, object);

	if (!ADBG_EXPECT_CK_RESULT(c, rv, expected_rc)) {
		rv = CKR_GENERAL_ERROR;
		goto bail;
	}

	if (rv == CKR_OK) {
		if (mode == TEE_MODE_ENCRYPT)
			rv = C_EncryptFinal(session, NULL, NULL);
		if (mode == TEE_MODE_DECRYPT)
			rv = C_DecryptFinal(session, NULL, NULL);

		/* Only check that the operation is no more active */
		if (!ADBG_EXPECT_TRUE(c, rv != CKR_BUFFER_TOO_SMALL)) {
			rv = CKR_GENERAL_ERROR;
			goto bail;
		}
	}

	rv = C_DestroyObject(session, object);
	if (!ADBG_EXPECT_CK_OK(c, rv))
		goto bail;

bail:
	return rv;
}

CK_KEY_ALLOWED_AES_ENC_TEST(cktest_aes_enc_only_cts, allowed_only_aes_cts);
CK_KEY_ALLOWED_AES_ENC_TEST(cktest_aes_enc_only_gcm, allowed_only_aes_gcm);

CK_KEY_ALLOWED_AES_DEC_TEST(cktest_aes_dec_only_ctr, allowed_only_aes_ctr);
CK_KEY_ALLOWED_AES_DEC_TEST(cktest_aes_dec_only_ccm, allowed_only_aes_ccm);

static void xtest_tee_test_4108(ADBG_Case_t *c)
{
	CK_RV rv;
	CK_SLOT_ID slot;
	CK_SESSION_HANDLE session = CK_INVALID_HANDLE;
	CK_FLAGS session_flags = CKF_SERIAL_SESSION;
	size_t n;

	rv = init_lib_and_find_token_slot(&slot);
	if (!ADBG_EXPECT_CK_OK(c, rv))
		return;

	rv = C_OpenSession(slot, session_flags, NULL, 0, &session);
	if (!ADBG_EXPECT_CK_OK(c, rv))
		goto bail;

	for (n = 0; n < ARRAY_SIZE(cktest_allowed_valid); n++) {

		Do_ADBG_BeginSubCase(c, "valid usage #%u", n);

		rv = cipher_init_final(c, session,
					cktest_allowed_valid[n].attr_key,
					cktest_allowed_valid[n].attr_count,
					cktest_allowed_valid[n].mechanism,
					TEE_MODE_ENCRYPT,
					CKR_OK);

		ADBG_EXPECT_CK_OK(c, rv);

		Do_ADBG_EndSubCase(c, NULL);
		if (rv)
			goto bail;

	}

	for (n = 0; n < ARRAY_SIZE(cktest_allowed_invalid); n++) {
		Do_ADBG_BeginSubCase(c, "invalid usage #%u", n);

		rv = cipher_init_final(c, session,
					cktest_allowed_invalid[n].attr_key,
					cktest_allowed_invalid[n].attr_count,
					cktest_allowed_invalid[n].mechanism,
					TEE_MODE_ENCRYPT,
					CKR_KEY_FUNCTION_NOT_PERMITTED);

		ADBG_EXPECT_CK_OK(c, rv);

		Do_ADBG_EndSubCase(c, NULL);
		if (rv)
			goto bail;

	}

bail:
	rv = C_CloseSession(session);
	ADBG_EXPECT_CK_OK(c, rv);

	rv = close_lib();
	ADBG_EXPECT_CK_OK(c, rv);
}

static void xtest_tee_test_4109(ADBG_Case_t *c)
{
	CK_RV rv;
	CK_SLOT_ID slot;
	CK_SESSION_HANDLE session = CK_INVALID_HANDLE;
	CK_FLAGS session_flags = CKF_SERIAL_SESSION;

	rv = init_lib_and_find_token_slot(&slot);
	if (!ADBG_EXPECT_CK_OK(c, rv))
		return;

	rv = C_OpenSession(slot, session_flags, NULL, 0, &session);
	if (!ADBG_EXPECT_CK_OK(c, rv))
		goto bail;

	/* Encrypt only AES CTS key */
	rv = cipher_init_final(c, session,
				cktest_aes_enc_only_cts,
				ARRAY_SIZE(cktest_aes_enc_only_cts),
				&cktest_aes_cts_mechanism,
				TEE_MODE_ENCRYPT,
				CKR_OK);
	if (!ADBG_EXPECT_CK_OK(c, rv))
		goto bail;

	rv = cipher_init_final(c, session,
				cktest_aes_enc_only_cts,
				ARRAY_SIZE(cktest_aes_enc_only_cts),
				&cktest_aes_cts_mechanism,
				TEE_MODE_DECRYPT,
				CKR_KEY_FUNCTION_NOT_PERMITTED);
	if (!ADBG_EXPECT_CK_OK(c, rv))
		goto bail;

	/* Decrypt only AES CTR key */
	rv = cipher_init_final(c, session,
				cktest_aes_dec_only_ctr,
				ARRAY_SIZE(cktest_aes_dec_only_ctr),
				&cktest_aes_ctr_mechanism,
				TEE_MODE_ENCRYPT,
				CKR_KEY_FUNCTION_NOT_PERMITTED);
	if (!ADBG_EXPECT_CK_OK(c, rv))
		goto bail;

	rv = cipher_init_final(c, session,
				cktest_aes_dec_only_ctr,
				ARRAY_SIZE(cktest_aes_dec_only_ctr),
				&cktest_aes_ctr_mechanism,
				TEE_MODE_ENCRYPT,
				CKR_KEY_FUNCTION_NOT_PERMITTED);
	if (!ADBG_EXPECT_CK_OK(c, rv))
		goto bail;

	/* Encrypt only AES GCM key */
	rv = cipher_init_final(c, session,
				cktest_aes_enc_only_gcm,
				ARRAY_SIZE(cktest_aes_enc_only_gcm),
				&cktest_aes_gcm_mechanism,
				TEE_MODE_ENCRYPT,
				CKR_OK);
	if (!ADBG_EXPECT_CK_OK(c, rv))
		goto bail;

	rv = cipher_init_final(c, session,
				cktest_aes_enc_only_gcm,
				ARRAY_SIZE(cktest_aes_enc_only_gcm),
				&cktest_aes_gcm_mechanism,
				TEE_MODE_DECRYPT,
				CKR_KEY_FUNCTION_NOT_PERMITTED);
	if (!ADBG_EXPECT_CK_OK(c, rv))
		goto bail;

	/* Decrypt only AES CCM key */
	rv = cipher_init_final(c, session,
				cktest_aes_dec_only_ccm,
				ARRAY_SIZE(cktest_aes_dec_only_ccm),
				&cktest_aes_ccm_mechanism,
				TEE_MODE_DECRYPT,
				CKR_OK);
	if (!ADBG_EXPECT_CK_OK(c, rv))
		goto bail;

	rv = cipher_init_final(c, session,
				cktest_aes_dec_only_ccm,
				ARRAY_SIZE(cktest_aes_dec_only_ccm),
				&cktest_aes_ccm_mechanism,
				TEE_MODE_ENCRYPT,
				CKR_KEY_FUNCTION_NOT_PERMITTED);
	if (!ADBG_EXPECT_CK_OK(c, rv))
		goto bail;

bail:
	rv = C_CloseSession(session);
	ADBG_EXPECT_CK_OK(c, rv);

	rv = close_lib();
	ADBG_EXPECT_CK_OK(c, rv);
}

static void xtest_tee_test_4110(ADBG_Case_t *c)
{
	cktest_in_regression_40xx(c, 4110);
}

static void xtest_tee_test_4111(ADBG_Case_t *c)
{
	cktest_in_regression_40xx(c, 4111);
}

static void xtest_tee_test_4112(ADBG_Case_t *c)
{
	cktest_in_regression_40xx(c, 4112);
}

static CK_RV open_cipher_session(ADBG_Case_t *c,
				 CK_SLOT_ID slot, CK_SESSION_HANDLE_PTR session,
				 CK_ATTRIBUTE_PTR attr_key, CK_ULONG attr_count,
				 CK_MECHANISM_PTR mechanism, uint32_t mode)
{
	CK_RV rv;
	CK_OBJECT_HANDLE object;
	CK_FLAGS session_flags = CKF_SERIAL_SESSION;

	switch (mode) {
	case TEE_MODE_ENCRYPT:
	case TEE_MODE_DECRYPT:
		break;
	default:
		ADBG_EXPECT_TRUE(c, false);
		return CKR_GENERAL_ERROR;
	}

	rv = C_OpenSession(slot, session_flags, NULL, 0, session);
	if (rv == CKR_DEVICE_MEMORY)
		goto bail;
	if (!ADBG_EXPECT_CK_OK(c, rv))
		goto bail;

	rv = C_CreateObject(*session, attr_key, attr_count, &object);
	if (rv == CKR_DEVICE_MEMORY)
		return rv;
	if (!ADBG_EXPECT_CK_OK(c, rv))
		goto bail;

	if (mode == TEE_MODE_ENCRYPT)
		rv = C_EncryptInit(*session, mechanism, object);
	if (mode == TEE_MODE_DECRYPT)
		rv = C_DecryptInit(*session, mechanism, object);

	if (rv == CKR_DEVICE_MEMORY)
		return rv;
	if (!ADBG_EXPECT_CK_OK(c, rv)) {
		rv = CKR_GENERAL_ERROR;
		goto bail;
	}

bail:
	return rv;
}

static void xtest_tee_test_4113(ADBG_Case_t *c)
{
	CK_RV rv;
	CK_SLOT_ID slot;
	CK_SESSION_HANDLE sessions[128];
	size_t n;

	for (n = 0; n < ARRAY_SIZE(sessions); n++)
		sessions[n] = CK_INVALID_HANDLE;

	rv = init_lib_and_find_token_slot(&slot);
	if (!ADBG_EXPECT_CK_OK(c, rv))
		return;

	for (n = 0; n < ARRAY_SIZE(sessions); n++) {

		rv = open_cipher_session(c, slot, &sessions[n],
					 cktest_allowed_valid[0].attr_key,
					 cktest_allowed_valid[0].attr_count,
					 cktest_allowed_valid[0].mechanism,
					 TEE_MODE_ENCRYPT);

		/* Failure due to memory allocation is not a error case */
		if (rv == CKR_DEVICE_MEMORY)
			break;

		if (!ADBG_EXPECT_CK_OK(c, rv))
			goto bail;
	}

	if (!ADBG_EXPECT_COMPARE_UNSIGNED(c, n, >, 0))
		goto bail;

	Do_ADBG_Log("    created sessions count: %zu", n);

	/* Closing session with out bound and invalid IDs (or negative ID) */
	rv = C_CloseSession(sessions[n - 1] + 1024);
	ADBG_EXPECT_CK_RESULT(c, rv, CKR_SESSION_HANDLE_INVALID);
	rv = C_CloseSession(CK_INVALID_HANDLE);
	ADBG_EXPECT_CK_RESULT(c, rv, CKR_SESSION_HANDLE_INVALID);
	rv = C_CloseSession(~0);
	ADBG_EXPECT_CK_RESULT(c, rv, CKR_SESSION_HANDLE_INVALID);

	/* Closing each session: all related resources shall be free */
	for (n = 0; n < ARRAY_SIZE(sessions); n++) {
		if (sessions[n] == CK_INVALID_HANDLE)
			continue;

		rv = C_CloseSession(sessions[n]);
		ADBG_EXPECT_CK_OK(c, rv);
		sessions[n] = CK_INVALID_HANDLE;
	}

	/* Open and close another session */
	rv = open_cipher_session(c, slot, sessions,
				 cktest_allowed_valid[0].attr_key,
				 cktest_allowed_valid[0].attr_count,
				 cktest_allowed_valid[0].mechanism,
				 TEE_MODE_ENCRYPT);

	if (!ADBG_EXPECT_CK_OK(c, rv))
		goto bail;

	rv = C_CloseSession(sessions[0]);
	ADBG_EXPECT_CK_OK(c, rv);
	sessions[0] = CK_INVALID_HANDLE;

bail:
	for (n = 0; n < ARRAY_SIZE(sessions); n++) {
		if (sessions[n] == CK_INVALID_HANDLE)
			continue;

		rv = C_CloseSession(sessions[n]);
		ADBG_EXPECT_CK_OK(c, rv);
	}

	rv = close_lib();
	ADBG_EXPECT_CK_OK(c, rv);
}

static CK_ATTRIBUTE cktest_object_aes_private[] = {
	{ CKA_ENCRYPT, &(CK_BBOOL){CK_TRUE}, sizeof(CK_BBOOL) },
	{ CKA_DECRYPT, &(CK_BBOOL){CK_TRUE}, sizeof(CK_BBOOL) },
	{ CKA_TOKEN, &(CK_BBOOL){CK_TRUE}, sizeof(CK_BBOOL) },
	{ CKA_PRIVATE, &(CK_BBOOL){CK_TRUE}, sizeof(CK_BBOOL) },
	{ CKA_EXTRACTABLE, &(CK_BBOOL){CK_TRUE}, sizeof(CK_BBOOL) },
	{ CKA_MODIFIABLE, &(CK_BBOOL){CK_FALSE}, sizeof(CK_BBOOL) },
	{ CKA_COPYABLE, &(CK_BBOOL){CK_FALSE}, sizeof(CK_BBOOL) },
	{ CKA_CLASS, &(CK_OBJECT_CLASS){CKO_SECRET_KEY},
			sizeof(CK_OBJECT_CLASS) },
	{ CKA_KEY_TYPE,	&(CK_KEY_TYPE){CKK_AES}, sizeof(CK_KEY_TYPE) },
	{ CKA_VALUE, (void *)cktest_aes128_key, sizeof(cktest_aes128_key) },
};

static CK_ATTRIBUTE cktest_object_aes_sensitive[] = {
	{ CKA_ENCRYPT, &(CK_BBOOL){CK_TRUE}, sizeof(CK_BBOOL) },
	{ CKA_DECRYPT, &(CK_BBOOL){CK_TRUE}, sizeof(CK_BBOOL) },
	{ CKA_TOKEN, &(CK_BBOOL){CK_TRUE}, sizeof(CK_BBOOL) },
	{ CKA_SENSITIVE, &(CK_BBOOL){CK_TRUE}, sizeof(CK_BBOOL) },
	{ CKA_EXTRACTABLE, &(CK_BBOOL){CK_TRUE}, sizeof(CK_BBOOL) },
	{ CKA_MODIFIABLE, &(CK_BBOOL){CK_FALSE}, sizeof(CK_BBOOL) },
	{ CKA_COPYABLE, &(CK_BBOOL){CK_FALSE}, sizeof(CK_BBOOL) },
	{ CKA_CLASS, &(CK_OBJECT_CLASS){CKO_SECRET_KEY},
			sizeof(CK_OBJECT_CLASS) },
	{ CKA_KEY_TYPE,	&(CK_KEY_TYPE){CKK_AES}, sizeof(CK_KEY_TYPE) },
	{ CKA_VALUE, (void *)cktest_aes128_key, sizeof(cktest_aes128_key) },
};

static CK_ATTRIBUTE cktest_object_pers_aes_dec[] = {
	{ CKA_DECRYPT, &(CK_BBOOL){CK_TRUE}, sizeof(CK_BBOOL) },
	{ CKA_TOKEN, &(CK_BBOOL){CK_TRUE}, sizeof(CK_BBOOL) },
	{ CKA_MODIFIABLE, &(CK_BBOOL){CK_TRUE}, sizeof(CK_BBOOL) },
	{ CKA_CLASS, &(CK_OBJECT_CLASS){CKO_SECRET_KEY},
			sizeof(CK_OBJECT_CLASS) },
	{ CKA_KEY_TYPE, &(CK_KEY_TYPE){CKK_AES}, sizeof(CK_KEY_TYPE) },
	{ CKA_VALUE, (void *)cktest_aes128_key, sizeof(cktest_aes128_key) },
};

static CK_ATTRIBUTE cktest_object_pers_aes_enc[] = {
	{ CKA_ENCRYPT, &(CK_BBOOL){CK_TRUE}, sizeof(CK_BBOOL) },
	{ CKA_TOKEN, &(CK_BBOOL){CK_TRUE}, sizeof(CK_BBOOL) },
	{ CKA_MODIFIABLE, &(CK_BBOOL){CK_TRUE}, sizeof(CK_BBOOL) },
	{ CKA_CLASS, &(CK_OBJECT_CLASS){CKO_SECRET_KEY},
			sizeof(CK_OBJECT_CLASS) },
	{ CKA_KEY_TYPE, &(CK_KEY_TYPE){CKK_AES}, sizeof(CK_KEY_TYPE) },
	{ CKA_VALUE, (void *)cktest_aes128_key, sizeof(cktest_aes128_key) },
};

static CK_ATTRIBUTE cktest_object_aes_dec[]  = {
	{ CKA_DECRYPT, &(CK_BBOOL){CK_TRUE}, sizeof(CK_BBOOL) },
	{ CKA_MODIFIABLE, &(CK_BBOOL){CK_TRUE}, sizeof(CK_BBOOL) },
	{ CKA_KEY_TYPE, &(CK_KEY_TYPE){CKK_AES}, sizeof(CK_KEY_TYPE) },
	{ CKA_CLASS, &(CK_OBJECT_CLASS){CKO_SECRET_KEY},
			sizeof(CK_OBJECT_CLASS) },
	{ CKA_VALUE, (void *)cktest_aes128_key, sizeof(cktest_aes128_key) },
};

static CK_ATTRIBUTE cktest_object_aes_enc[] = {
	{ CKA_ENCRYPT, &(CK_BBOOL){CK_TRUE}, sizeof(CK_BBOOL) },
	{ CKA_MODIFIABLE, &(CK_BBOOL){CK_TRUE}, sizeof(CK_BBOOL) },
	{ CKA_KEY_TYPE, &(CK_KEY_TYPE){CKK_AES}, sizeof(CK_KEY_TYPE) },
	{ CKA_CLASS, &(CK_OBJECT_CLASS){CKO_SECRET_KEY},
			sizeof(CK_OBJECT_CLASS) },
	{ CKA_VALUE, (void *)cktest_aes128_key, sizeof(cktest_aes128_key) },
};

static CK_ATTRIBUTE cktest_findobj_aes_dec[] = {
	{ CKA_DECRYPT, &(CK_BBOOL){CK_TRUE}, sizeof(CK_BBOOL) },
	{ CKA_KEY_TYPE, &(CK_KEY_TYPE){CKK_AES}, sizeof(CK_KEY_TYPE) },
	{ CKA_CLASS, &(CK_OBJECT_CLASS){CKO_SECRET_KEY},
			sizeof(CK_OBJECT_CLASS) },
};

static CK_ATTRIBUTE cktest_findobj_aes_enc[] = {
	{ CKA_ENCRYPT, &(CK_BBOOL){CK_TRUE}, sizeof(CK_BBOOL) },
	{ CKA_KEY_TYPE, &(CK_KEY_TYPE){CKK_AES}, sizeof(CK_KEY_TYPE) },
	{ CKA_CLASS, &(CK_OBJECT_CLASS){CKO_SECRET_KEY},
			sizeof(CK_OBJECT_CLASS) },
};

static CK_ATTRIBUTE cktest_findobj_pers_aes_enc[] = {
	{ CKA_ENCRYPT, &(CK_BBOOL){CK_TRUE}, sizeof(CK_BBOOL) },
	{ CKA_TOKEN, &(CK_BBOOL){CK_TRUE}, sizeof(CK_BBOOL) },
	{ CKA_KEY_TYPE, &(CK_KEY_TYPE){CKK_AES}, sizeof(CK_KEY_TYPE) },
	{ CKA_CLASS, &(CK_OBJECT_CLASS){CKO_SECRET_KEY},
			sizeof(CK_OBJECT_CLASS) },
};

static CK_ATTRIBUTE cktest_findobj_sess_aes_enc[] = {
	{ CKA_ENCRYPT, &(CK_BBOOL){CK_TRUE}, sizeof(CK_BBOOL) },
	{ CKA_TOKEN, &(CK_BBOOL){CK_FALSE}, sizeof(CK_BBOOL) },
	{ CKA_KEY_TYPE, &(CK_KEY_TYPE){CKK_AES}, sizeof(CK_KEY_TYPE) },
	{ CKA_CLASS, &(CK_OBJECT_CLASS){CKO_SECRET_KEY},
			sizeof(CK_OBJECT_CLASS) },
};

static CK_ATTRIBUTE cktest_findobj_pers_aes[] = {
	{ CKA_TOKEN, &(CK_BBOOL){CK_TRUE}, sizeof(CK_BBOOL) },
	{ CKA_KEY_TYPE, &(CK_KEY_TYPE){CKK_AES}, sizeof(CK_KEY_TYPE) },
	{ CKA_CLASS, &(CK_OBJECT_CLASS){CKO_SECRET_KEY},
			sizeof(CK_OBJECT_CLASS) },
};

static void destroy_persistent_objects(ADBG_Case_t *c, CK_SLOT_ID slot)
{
	uint32_t rv;
	CK_SESSION_HANDLE session = CK_INVALID_HANDLE;
	CK_FLAGS session_flags = CKF_SERIAL_SESSION | CKF_RW_SESSION;
	CK_OBJECT_HANDLE obj_hdl = CK_INVALID_HANDLE;
	CK_ULONG count = 1;
	CK_ATTRIBUTE cktest_find_all_token_objs[] = {
		{ CKA_TOKEN, &(CK_BBOOL){CK_TRUE}, sizeof(CK_BBOOL) },
	};

	rv = init_user_test_token(slot);
	if (!ADBG_EXPECT_CK_OK(c, rv))
		return;

	rv = C_OpenSession(slot, session_flags, NULL, 0, &session);
	if (!ADBG_EXPECT_CK_OK(c, rv))
		return;

	/* Login to destroy private objects */
	rv = login_user_test_token(session);
	if (!ADBG_EXPECT_CK_OK(c, rv))
		goto bail;

	rv = C_FindObjectsInit(session, cktest_find_all_token_objs,
			    ARRAY_SIZE(cktest_find_all_token_objs));
	if (!ADBG_EXPECT_CK_OK(c, rv))
		goto bail;

	while (1) {
		rv = C_FindObjects(session, &obj_hdl, 1, &count);
		if (!ADBG_EXPECT_CK_OK(c, rv))
			goto bail;
		if (!count)
			break;

		rv = C_DestroyObject(session, obj_hdl);
		ADBG_EXPECT_CK_OK(c, rv);
	}

	rv = C_FindObjectsFinal(session);
	ADBG_EXPECT_CK_OK(c, rv);

	rv = logout_test_token(session);
	ADBG_EXPECT_CK_OK(c, rv);

bail:
	rv = C_CloseSession(session);
	ADBG_EXPECT_CK_OK(c, rv);
}

static void xtest_tee_test_4114(ADBG_Case_t *c)
{
	CK_RV rv;
	CK_SLOT_ID slot;
	CK_SESSION_HANDLE session = CK_INVALID_HANDLE;
	CK_OBJECT_HANDLE obj_hdl[10];
	CK_OBJECT_HANDLE obj_found[10];
	CK_FLAGS session_flags = CKF_SERIAL_SESSION | CKF_RW_SESSION;
	CK_ULONG hdl_count;
	size_t n;

	for (n = 0; n < ARRAY_SIZE(obj_hdl); n++)
		obj_hdl[n] = CK_INVALID_HANDLE;
	for (n = 0; n < ARRAY_SIZE(obj_found); n++)
		obj_found[n] = CK_INVALID_HANDLE;

	rv = init_lib_and_find_token_slot(&slot);
	if (!ADBG_EXPECT_CK_OK(c, rv))
		return;

	/*
	 * Sub test: create persistent and session objects and find them
	 */
	Do_ADBG_BeginSubCase(c, "Find created AES key objects");

	rv = C_OpenSession(slot, session_flags, NULL, 0, &session);
	if (!ADBG_EXPECT_CK_OK(c, rv))
		goto bail0;

	rv = C_CreateObject(session, cktest_object_aes_dec,
			    ARRAY_SIZE(cktest_object_aes_dec),
			    &obj_hdl[0]);
	if (!ADBG_EXPECT_CK_OK(c, rv))
		goto bail;

	rv = C_CreateObject(session, cktest_object_aes_enc,
			    ARRAY_SIZE(cktest_object_aes_enc),
			    &obj_hdl[1]);
	if (!ADBG_EXPECT_CK_OK(c, rv))
		goto bail;

	rv = C_CreateObject(session, cktest_object_pers_aes_dec,
			    ARRAY_SIZE(cktest_object_pers_aes_dec),
			    &obj_hdl[2]);
	if (!ADBG_EXPECT_CK_OK(c, rv))
		goto bail;

	rv = C_CreateObject(session, cktest_object_pers_aes_enc,
			    ARRAY_SIZE(cktest_object_pers_aes_enc),
			    &obj_hdl[3]);
	if (!ADBG_EXPECT_CK_OK(c, rv))
		goto bail;

	rv = C_FindObjectsInit(session, cktest_findobj_aes_dec,
				ARRAY_SIZE(cktest_findobj_aes_dec));
	if (!ADBG_EXPECT_CK_OK(c, rv))
		goto bail;

	rv = C_FindObjects(session,
			   obj_found, ARRAY_SIZE(obj_found), &hdl_count);

	if (!ADBG_EXPECT_CK_OK(c, rv) ||
	    !ADBG_EXPECT_COMPARE_UNSIGNED(c, hdl_count, ==, 2) ||
	    !ADBG_EXPECT_TRUE(c, (obj_found[0] == obj_hdl[0]) ||
				 (obj_found[0] == obj_hdl[2])) ||
	    !ADBG_EXPECT_TRUE(c, (obj_found[1] == obj_hdl[0]) ||
				 (obj_found[1] == obj_hdl[2])))
		goto bail;

	rv = C_FindObjectsFinal(session);
	if (!ADBG_EXPECT_CK_OK(c, rv))
		goto bail;

	Do_ADBG_EndSubCase(c, NULL);
	/*
	 * Sub test: again but get handles one by one
	 */
	Do_ADBG_BeginSubCase(c, "Find one by one created AES key objects");

	rv = C_FindObjectsInit(session, cktest_findobj_aes_enc,
				ARRAY_SIZE(cktest_findobj_aes_enc));
	if (!ADBG_EXPECT_CK_OK(c, rv))
		goto bail;

	rv = C_FindObjects(session, obj_found, 1, &hdl_count);

	if (!ADBG_EXPECT_CK_OK(c, rv) ||
	    !ADBG_EXPECT_COMPARE_UNSIGNED(c, hdl_count, ==, 1) ||
	    !ADBG_EXPECT_TRUE(c, (obj_found[0] == obj_hdl[1]) ||
				 (obj_found[0] == obj_hdl[3])))
		goto bail;

	rv = C_FindObjects(session, &obj_found[1], 1, &hdl_count);

	if (!ADBG_EXPECT_CK_OK(c, rv) ||
	    !ADBG_EXPECT_COMPARE_UNSIGNED(c, hdl_count, ==, 1) ||
	    !ADBG_EXPECT_TRUE(c, (obj_found[1] == obj_hdl[1]) ||
				 (obj_found[1] == obj_hdl[3])) ||
	    !ADBG_EXPECT_TRUE(c, (obj_found[1] != obj_found[0])))
		goto bail;

	rv = C_FindObjects(session, obj_found, 1, &hdl_count);

	if (!ADBG_EXPECT_CK_OK(c, rv) ||
	    !ADBG_EXPECT_COMPARE_UNSIGNED(c, hdl_count, ==, 0))
		goto bail;

	rv = C_FindObjectsFinal(session);
	if (!ADBG_EXPECT_CK_OK(c, rv))
		goto bail;

	Do_ADBG_EndSubCase(c, NULL);
	/*
	 * Sub test: search for a persistent object only
	 */
	Do_ADBG_BeginSubCase(c, "Find persistent objects");

	rv = C_FindObjectsInit(session, cktest_findobj_pers_aes_enc,
				ARRAY_SIZE(cktest_findobj_pers_aes_enc));
	if (!ADBG_EXPECT_CK_OK(c, rv))
		goto bail;

	rv = C_FindObjects(session,
			   obj_found, ARRAY_SIZE(obj_found), &hdl_count);

	if (!ADBG_EXPECT_CK_OK(c, rv) ||
	    !ADBG_EXPECT_COMPARE_UNSIGNED(c, hdl_count, ==, 1) ||
	    !ADBG_EXPECT_TRUE(c, (obj_found[0] == obj_hdl[3])))
		goto bail;

	rv = C_FindObjectsFinal(session);
	if (!ADBG_EXPECT_CK_OK(c, rv))
		goto bail;

	Do_ADBG_EndSubCase(c, NULL);
	/*
	 * Sub test: search for a session object only
	 */
	Do_ADBG_BeginSubCase(c, "Find session objects");

	rv = C_FindObjectsInit(session, cktest_findobj_sess_aes_enc,
				ARRAY_SIZE(cktest_findobj_sess_aes_enc));
	if (!ADBG_EXPECT_CK_OK(c, rv))
		goto bail;

	rv = C_FindObjects(session,
			   obj_found, ARRAY_SIZE(obj_found), &hdl_count);

	if (!ADBG_EXPECT_CK_OK(c, rv) ||
	    !ADBG_EXPECT_COMPARE_UNSIGNED(c, hdl_count, ==, 1) ||
	    !ADBG_EXPECT_TRUE(c, (obj_found[0] == obj_hdl[1])))
		goto bail;

	rv = C_FindObjectsFinal(session);
	if (!ADBG_EXPECT_CK_OK(c, rv))
		goto bail;

	Do_ADBG_EndSubCase(c, NULL);
	/*
	 * Sub test: search object from a brand new session
	 */
	Do_ADBG_BeginSubCase(c, "Find object from a new session");

	rv = C_CloseSession(session);
	ADBG_EXPECT_CK_OK(c, rv);

	rv = C_OpenSession(slot, session_flags, NULL, 0, &session);
	if (!ADBG_EXPECT_CK_OK(c, rv))
		goto bail0;

	rv = C_FindObjectsInit(session, cktest_findobj_sess_aes_enc,
				ARRAY_SIZE(cktest_findobj_sess_aes_enc));
	if (!ADBG_EXPECT_CK_OK(c, rv))
		goto bail;

	rv = C_FindObjects(session,
			   obj_found, ARRAY_SIZE(obj_found), &hdl_count);

	if (!ADBG_EXPECT_CK_OK(c, rv) ||
	    !ADBG_EXPECT_COMPARE_UNSIGNED(c, hdl_count, ==, 0))
		goto bail;

	rv = C_FindObjectsFinal(session);
	if (!ADBG_EXPECT_CK_OK(c, rv))
		goto bail;

	rv = C_FindObjectsInit(session, cktest_findobj_pers_aes,
				ARRAY_SIZE(cktest_findobj_pers_aes));
	if (!ADBG_EXPECT_CK_OK(c, rv))
		goto bail;

	rv = C_FindObjects(session,
			   obj_found, ARRAY_SIZE(obj_found), &hdl_count);

	if (!ADBG_EXPECT_CK_OK(c, rv) ||
	    !ADBG_EXPECT_COMPARE_UNSIGNED(c, hdl_count, ==, 2))
		goto bail;

	rv = C_FindObjectsFinal(session);
	if (!ADBG_EXPECT_CK_OK(c, rv))
		goto bail;

	Do_ADBG_EndSubCase(c, NULL);
	/*
	 * Sub test: finalize search without getting the handles found
	 */
	Do_ADBG_BeginSubCase(c, "Initiate and finalize straight a search");

	rv = C_FindObjectsInit(session, cktest_findobj_pers_aes,
				ARRAY_SIZE(cktest_findobj_pers_aes));
	if (!ADBG_EXPECT_CK_OK(c, rv))
		goto bail;

	rv = C_FindObjectsFinal(session);
	if (!ADBG_EXPECT_CK_OK(c, rv))
		goto bail;

	Do_ADBG_EndSubCase(c, NULL);
	/*
	 * Sub test: invalid call cases
	 */
	Do_ADBG_BeginSubCase(c, "Various invalid invocation cases");

	rv = C_FindObjectsFinal(session);
	ADBG_EXPECT_CK_RESULT(c, rv, CKR_OPERATION_NOT_INITIALIZED);

	rv = C_FindObjects(session,
			   obj_found, ARRAY_SIZE(obj_found), &hdl_count);
	ADBG_EXPECT_CK_RESULT(c, rv, CKR_OPERATION_NOT_INITIALIZED);

	rv = C_FindObjectsInit(session, cktest_findobj_pers_aes,
				ARRAY_SIZE(cktest_findobj_pers_aes));
	if (!ADBG_EXPECT_CK_OK(c, rv))
		goto bail;

	rv = C_FindObjectsInit(session, cktest_findobj_pers_aes,
				ARRAY_SIZE(cktest_findobj_pers_aes));
	ADBG_EXPECT_COMPARE_UNSIGNED(c, rv, !=, CKR_OK);

	rv = C_FindObjectsFinal(session);
	ADBG_EXPECT_CK_OK(c, rv);

	rv = C_FindObjectsInit(session, cktest_findobj_pers_aes,
				ARRAY_SIZE(cktest_findobj_pers_aes));
	ADBG_EXPECT_CK_OK(c, rv);

	/*
	 * Intentianlly do not finalize the active object search. It should
	 * be released together with the session closure.
	 */
bail:
	/* TODO: destroy persistent objects!!! */
	rv = C_CloseSession(session);
	ADBG_EXPECT_CK_OK(c, rv);

bail0:
	destroy_persistent_objects(c, slot);

	rv = close_lib();
	ADBG_EXPECT_CK_OK(c, rv);

	Do_ADBG_EndSubCase(c, NULL);
}

static void xtest_tee_test_4115(ADBG_Case_t *c)
{
	CK_RV rv;
	CK_SLOT_ID slot;
	CK_SESSION_HANDLE session = CK_INVALID_HANDLE;
	CK_OBJECT_HANDLE obj_hdl[10];
	CK_OBJECT_HANDLE obj_found[10];
	CK_FLAGS session_flags = CKF_SERIAL_SESSION | CKF_RW_SESSION;
	CK_ULONG hdl_count;
	size_t n;

	for (n = 0; n < ARRAY_SIZE(obj_hdl); n++)
		obj_hdl[n] = CK_INVALID_HANDLE;
	for (n = 0; n < ARRAY_SIZE(obj_found); n++)
		obj_found[n] = CK_INVALID_HANDLE;

	/* Create test setup; persistent objects, user log support */
	rv = init_lib_and_find_token_slot(&slot);
	if (!ADBG_EXPECT_CK_OK(c, rv))
		return;

	rv = init_user_test_token(slot);
	if (!ADBG_EXPECT_CK_OK(c, rv))
		goto bail0;

	rv = C_OpenSession(slot, session_flags, NULL, 0, &session);
	if (!ADBG_EXPECT_CK_OK(c, rv))
		goto bail0;

	rv = C_CreateObject(session, cktest_object_aes_sensitive,
			    ARRAY_SIZE(cktest_object_aes_sensitive),
			    &obj_hdl[4]);
	if (!ADBG_EXPECT_CK_OK(c, rv))
		goto bail;

	rv = C_CreateObject(session, cktest_object_aes_private,
			    ARRAY_SIZE(cktest_object_aes_private),
			    &obj_hdl[0]);
	if (!ADBG_EXPECT_CK_OK(c, rv))
		goto bail;

	rv = C_CreateObject(session, cktest_object_pers_aes_enc,
			    ARRAY_SIZE(cktest_object_pers_aes_enc),
			    &obj_hdl[1]);
	if (!ADBG_EXPECT_CK_OK(c, rv))
		goto bail;

	rv = close_lib();
	ADBG_EXPECT_CK_OK(c, rv);

	/*
	 * Not logged: find (public) objects
	 */

	rv = init_lib_and_find_token_slot(&slot);
	if (!ADBG_EXPECT_CK_OK(c, rv))
		return;

	rv = C_OpenSession(slot, session_flags, NULL, 0, &session);
	if (!ADBG_EXPECT_CK_OK(c, rv))
		goto bail0;

	rv = C_FindObjectsInit(session, cktest_findobj_aes_enc,
				ARRAY_SIZE(cktest_findobj_aes_enc));
	if (!ADBG_EXPECT_CK_OK(c, rv))
		goto bail;

	rv = C_FindObjects(session,
			   obj_found, ARRAY_SIZE(obj_found), &hdl_count);

	ADBG_EXPECT_CK_OK(c, rv);
	ADBG_EXPECT_COMPARE_UNSIGNED(c, hdl_count, ==, 2);

	rv = C_FindObjectsFinal(session);
	if (!ADBG_EXPECT_CK_OK(c, rv))
		goto bail;

	rv = close_lib();
	ADBG_EXPECT_CK_OK(c, rv);

	/*
	 * Login and find (public and private) objects
	 */

	rv = init_lib_and_find_token_slot(&slot);
	if (!ADBG_EXPECT_CK_OK(c, rv))
		return;

	rv = C_OpenSession(slot, session_flags, NULL, 0, &session);
	if (!ADBG_EXPECT_CK_OK(c, rv))
		goto bail0;

	rv = login_user_test_token(session);
	if (!ADBG_EXPECT_CK_OK(c, rv))
		goto bail;

	rv = C_FindObjectsInit(session, cktest_findobj_aes_enc,
				ARRAY_SIZE(cktest_findobj_aes_enc));
	if (!ADBG_EXPECT_CK_OK(c, rv))
		goto bail;

	rv = C_FindObjects(session,
			   obj_found, ARRAY_SIZE(obj_found), &hdl_count);

	ADBG_EXPECT_CK_OK(c, rv);
	ADBG_EXPECT_COMPARE_UNSIGNED(c, hdl_count, ==, 3);

	rv = C_FindObjectsFinal(session);
	if (!ADBG_EXPECT_CK_OK(c, rv))
		goto bail;

	/*
	 * Logout and find (public only) objects
	 */

	rv = logout_test_token(session);
	if (!ADBG_EXPECT_CK_OK(c, rv))
		goto bail;

	rv = C_FindObjectsInit(session, cktest_findobj_aes_enc,
				ARRAY_SIZE(cktest_findobj_aes_enc));
	if (!ADBG_EXPECT_CK_OK(c, rv))
		goto bail;

	rv = C_FindObjects(session,
			   obj_found, ARRAY_SIZE(obj_found), &hdl_count);

	ADBG_EXPECT_CK_OK(c, rv);
	ADBG_EXPECT_COMPARE_UNSIGNED(c, hdl_count, ==, 2);

	rv = C_FindObjectsFinal(session);
	if (!ADBG_EXPECT_CK_OK(c, rv))
		goto bail;

bail:
	rv = C_CloseSession(session);
	ADBG_EXPECT_CK_OK(c, rv);

bail0:
	destroy_persistent_objects(c, slot);

	rv = close_lib();
	ADBG_EXPECT_CK_OK(c, rv);
}

static void xtest_tee_test_4116(ADBG_Case_t *c)
{
	cktest_in_regression_40xx(c, 4116);
}

static void xtest_tee_test_4117(ADBG_Case_t *c)
{
	cktest_in_regression_40xx(c, 4117);
}

ADBG_CASE_DEFINE(regression, 4101, xtest_tee_test_4101,
		"PKCS11: Initialize and close Cryptoki library");
ADBG_CASE_DEFINE(regression, 4102, xtest_tee_test_4102,
		"PKCS11: Connect token and get some token info");
ADBG_CASE_DEFINE(regression, 4103, xtest_tee_test_4103,
		"PKCS11: Open and close PKCS#11 sessions");
ADBG_CASE_DEFINE(regression, 4104, xtest_tee_test_4104,
		"PKCS11: Login tests (TODO: still weak)");
ADBG_CASE_DEFINE(regression, 4105, xtest_tee_test_4105,
		"PKCS11: Generate objects");
ADBG_CASE_DEFINE(regression, 4106, xtest_tee_test_4106,
		"PKCS11: Create and destroy sesion and token objects");
ADBG_CASE_DEFINE(regression, 4107, xtest_tee_test_4107,
		"PKCS11: Create objects in read-only and read-write sessions");
ADBG_CASE_DEFINE(regression, 4108, xtest_tee_test_4108,
		"PKCS11: Check ciphering with valid and invalid keys #1");
ADBG_CASE_DEFINE(regression, 4109, xtest_tee_test_4109,
		"PKCS11: Check ciphering with valid and invalid keys #2");
ADBG_CASE_DEFINE(regression, 4110, xtest_tee_test_4110,
		"PKCS11: Compliance of ciphering processings");
ADBG_CASE_DEFINE(regression, 4111, xtest_tee_test_4111,
		"PKCS11: Compliance of MAC signing processings");
ADBG_CASE_DEFINE(regression, 4112, xtest_tee_test_4112,
		"PKCS11: Compliance of AES CCM/GCM ciphering processings");
ADBG_CASE_DEFINE(regression, 4113, xtest_tee_test_4113, /*  TODO: rename 4110 */
		"PKCS11: Check operations release at session closure");
ADBG_CASE_DEFINE(regression, 4114, xtest_tee_test_4114,
		"PKCS11: Object lookup");
ADBG_CASE_DEFINE(regression, 4115, xtest_tee_test_4115,
		"PKCS11: Private object accesses");
ADBG_CASE_DEFINE(regression, 4116, xtest_tee_test_4116,
		"PKCS11: Test key generation");
ADBG_CASE_DEFINE(regression, 4117, xtest_tee_test_4117,
		"PKCS11: Compliance of asymmetric ciphering processings");
