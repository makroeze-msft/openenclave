// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#include <limits.h>
#include <openenclave/host.h>
#include <openenclave/internal/error.h>
#include <openenclave/internal/tests.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h> 
#include "tls_e2e_u.h"

#define SERVER_PORT "12345"
#define SERVER_IP "127.0.0.1"

typedef struct _tls_thread_context_config {
    oe_enclave_t* enclave;
    struct tls_control_args args;
} tls_thread_context_config_t;

typedef struct _tls_test_configs {
    tls_thread_context_config_t server;
    tls_thread_context_config_t client;
} tls_test_configs_t;

oe_enclave_t* g_server_enclave = NULL;
oe_enclave_t* g_client_enclave = NULL;

int g_server_thread_exit_code = 0;
int g_client_thread_exit_code = 0;

pthread_mutex_t server_mutex;
pthread_cond_t server_cond;
bool g_server_condition = false;
pthread_t server_thread_id;

int server_is_ready()
{
    printf("TLS server_is_ready!\n");
    pthread_mutex_lock(&server_mutex);
    g_server_condition = true;
    pthread_cond_signal(&server_cond); // Should wake up *one* thread
    pthread_mutex_unlock(&server_mutex);
    return 1;
}

oe_result_t enclave_identity_verifier(oe_identity_t* identity, void* arg)
{
    oe_result_t result = OE_VERIFY_FAILED;

    (void)arg;
    printf("enclave_identity_verifier is called with parsed report:\n");

    // Check the enclave's security version
    printf("identity.security_version = %d\n", identity->security_version);
    if (identity->security_version < 1)
    {
        printf("identity.security_version check failed (%d)\n", identity->security_version);
        goto done;
    }

    // the unique ID for the enclave
    // For SGX enclaves, this is the MRENCLAVE value
    printf("identity->signer_id :\n");
    for (int i = 0; i < OE_UNIQUE_ID_SIZE; i++)
    {
        printf("0x%0x ", (uint8_t)identity->signer_id[i]);
    }

    // The signer ID for the enclave.
    // For SGX enclaves, this is the MRSIGNER value
    printf("\nidentity->signer_id :\n");
    for (int i = 0; i < OE_SIGNER_ID_SIZE; i++)
    {
        printf("0x%0x ", (uint8_t)identity->signer_id[i]);
    }
    
    // The Product ID for the enclave.
    // For SGX enclaves, this is the ISVPRODID value
    printf("\nidentity->product_id :\n");
    for (int i = 0; i < OE_PRODUCT_ID_SIZE; i++)
    {
        printf("0x%0x ", (uint8_t)identity->product_id[i]);
    }
    result = OE_OK;
done:
    return result;
}

void *server_thread(void *arg) 
{
    oe_result_t result = OE_FAILURE;
    tls_thread_context_config_t* config = &(((tls_test_configs_t*)arg)->server);

    printf("Server thread starting\n"); 
    g_server_condition = false;
    result = setup_tls_server(config->enclave, &g_server_thread_exit_code, &(config->args), (char *)SERVER_PORT);
    if (result != OE_OK)
    {
        // unexpected, print error message and exit
        oe_put_err("Invoking ecall setup_tls_server() failed: result=%u", result);
    }

    printf("setup_tls_server(): g_server_thread_exit_code=[%d]\n", g_server_thread_exit_code);
    if ( config->args.fail_cert_verify_callback ||
         config->args.fail_enclave_identity_verifier_callback ||
         config->args.fail_oe_verify_tls_cert)
    {
        OE_TEST(g_server_thread_exit_code == 1);
    }

    printf("Leaving server thread...\n");
    fflush(stdout);
    pthread_exit((void*)&g_server_thread_exit_code);
} 

void *client_thread(void *arg)
{
    oe_result_t result = OE_FAILURE;
    tls_thread_context_config_t* client_config = &(((tls_test_configs_t*)arg)->client);
    tls_thread_context_config_t* server_config = &(((tls_test_configs_t*)arg)->server);
    void *retval = NULL;

    printf("Client thread: call launch_tls_client()\n");
    result = launch_tls_client(client_config->enclave, &g_client_thread_exit_code, &(client_config->args),
                              (char *)SERVER_IP, (char *)SERVER_PORT);
    if (result != OE_OK)
    {
        // unexpected, print error message and exit
        oe_put_err("Invoking ecall launch_tls_client() failed: result=%u", result);
    }
    printf("launch_tls_client() g_client_thread_exit_code=[%d]\n", g_client_thread_exit_code);

    if (client_config->args.fail_cert_verify_callback ||
        client_config->args.fail_enclave_identity_verifier_callback ||
        client_config->args.fail_oe_verify_tls_cert)
        OE_TEST(g_client_thread_exit_code != 0);
   // else
   //     OE_TEST(g_client_thread_exit_code == 0);

    printf("Waiting for the server thread to terminate...\n");
    // block client thread until the server thread is done
    pthread_join(server_thread_id, (void**)&retval);

    // enforce server return value
    printf("server returns retval = [%d]\n", *(int*)retval);
    if (server_config->args.fail_cert_verify_callback ||
        server_config->args.fail_enclave_identity_verifier_callback ||
        server_config->args.fail_oe_verify_tls_cert)
         OE_TEST(*(int*)(retval) == 1);

    pthread_exit((void*)&g_client_thread_exit_code);
    fflush(stdout);
}

// Return value:
int run_test_with_config(tls_test_configs_t* test_configs)
{
    pthread_attr_t server_tattr;
    pthread_attr_t client_tattr;
    pthread_t client_thread_id;
    int ret = 0;
    void *retval = NULL;

    // create server thread
    ret = pthread_attr_init(&server_tattr);
    if (ret)
        oe_put_err("pthread_attr_init(server): ret=%u", ret);

    ret = pthread_create(&server_thread_id, NULL, server_thread, (void *)test_configs);
    if (ret)
        oe_put_err("pthread_create(server): ret=%u", ret);

    printf("wait until TLS server is ready to accept client request\n");
    pthread_mutex_lock(&server_mutex);
    while(!g_server_condition)
        pthread_cond_wait(&server_cond, &server_mutex);
    pthread_mutex_unlock(&server_mutex);

    fflush(stdout);

    // create client thread
    ret = pthread_attr_init(&client_tattr);
    if (ret)
        oe_put_err("pthread_attr_init(client): ret=%u", ret);

    ret = pthread_create(&client_thread_id, NULL, client_thread, (void *)test_configs);
    if (ret)
        oe_put_err("pthread_create(client): ret=%u", ret);

    pthread_join(client_thread_id, &retval);
    ret = *(int*)retval;
    printf("Client thread terminated with ret =%d... \n", ret);
    return ret;
}

int test_normal_successful_scenario()
{
    tls_test_configs_t test_configs;
    int ret = 0;

    g_server_thread_exit_code = 0;
    g_client_thread_exit_code = 0;
    g_server_condition = false;

    printf("test_normal_successful_scenario\n");
    test_configs.server.enclave = g_server_enclave;
    test_configs.server.args.fail_cert_verify_callback = false;;
    test_configs.server.args.fail_enclave_identity_verifier_callback = false;
    test_configs.server.args.fail_oe_verify_tls_cert = false;

    test_configs.client.enclave = g_client_enclave;
    test_configs.client.args.fail_cert_verify_callback = false;;
    test_configs.client.args.fail_enclave_identity_verifier_callback = false;
    test_configs.client.args.fail_oe_verify_tls_cert = false;

    ret = run_test_with_config(&test_configs);
    printf("run_test_with_config returned %d\n", ret);
    return ret;
}

int test_server_fail_cert_verify_callback_scenario()
{
    tls_test_configs_t test_configs;
    int ret = 0;

    g_server_thread_exit_code = 0;
    g_client_thread_exit_code = 0;
    g_server_condition = false;

    printf("test_server_fail_cert_verify_callback_scenario\n");
    test_configs.server.enclave = g_server_enclave;
    test_configs.server.args.fail_cert_verify_callback = true;;
    test_configs.server.args.fail_enclave_identity_verifier_callback = false;
    test_configs.server.args.fail_oe_verify_tls_cert = false;

    test_configs.client.enclave = g_client_enclave;
    test_configs.client.args.fail_cert_verify_callback = false;;
    test_configs.client.args.fail_enclave_identity_verifier_callback = false;
    test_configs.client.args.fail_oe_verify_tls_cert = false;

    ret = run_test_with_config(&test_configs);
    printf("run_test_with_config returned %d\n", ret);
    return ret;
}

int test_server_fail_enclave_identity_verifier_callback_scenario()
{
    tls_test_configs_t test_configs;
    int ret = 0;

    g_server_thread_exit_code = 0;
    g_client_thread_exit_code = 0;
    g_server_condition = false;

    printf("test_server_fail_enclave_identity_verifier_callback_scenario\n");
    test_configs.server.enclave = g_server_enclave;
    test_configs.server.args.fail_cert_verify_callback = false;;
    test_configs.server.args.fail_enclave_identity_verifier_callback = true;
    test_configs.server.args.fail_oe_verify_tls_cert = false;

    test_configs.client.enclave = g_client_enclave;
    test_configs.client.args.fail_cert_verify_callback = false;;
    test_configs.client.args.fail_enclave_identity_verifier_callback = false;
    test_configs.client.args.fail_oe_verify_tls_cert = false;

    ret = run_test_with_config(&test_configs);
    printf("run_test_with_config returned %d\n", ret);
    return ret;
}

int test_server_fail_oe_verify_tls_cert_scenario()
{
    tls_test_configs_t test_configs;
    int ret = 0;

    g_server_thread_exit_code = 0;
    g_client_thread_exit_code = 0;
    g_server_condition = false;

    printf("test_server_fail_oe_verify_tls_cert_scenario\n");
    test_configs.server.enclave = g_server_enclave;
    test_configs.server.args.fail_cert_verify_callback = false;;
    test_configs.server.args.fail_enclave_identity_verifier_callback = false;
    test_configs.server.args.fail_oe_verify_tls_cert = true;

    test_configs.client.enclave = g_client_enclave;
    test_configs.client.args.fail_cert_verify_callback = false;;
    test_configs.client.args.fail_enclave_identity_verifier_callback = false;
    test_configs.client.args.fail_oe_verify_tls_cert = false;

    ret = run_test_with_config(&test_configs);
    printf("run_test_with_config returned %d\n", ret);
    return ret;
}

int test_client_fail_cert_verify_callback_scenario()
{
    tls_test_configs_t test_configs;
    int ret = 0;

    g_server_thread_exit_code = 0;
    g_client_thread_exit_code = 0;
    g_server_condition = false;

    printf("test_client_fail_cert_verify_callback_scenario\n");

    test_configs.server.enclave = g_server_enclave;
    test_configs.server.args.fail_cert_verify_callback = false;;
    test_configs.server.args.fail_enclave_identity_verifier_callback = false;
    test_configs.server.args.fail_oe_verify_tls_cert = false;

    test_configs.client.enclave = g_client_enclave;
    test_configs.client.args.fail_cert_verify_callback = true;;
    test_configs.client.args.fail_enclave_identity_verifier_callback = false;
    test_configs.client.args.fail_oe_verify_tls_cert = false;

    ret = run_test_with_config(&test_configs);
    printf("run_test_with_config returned %d\n", ret);
    return ret;
}

int test_client_fail_enclave_identity_verifier_callback_scenario()
{
    tls_test_configs_t test_configs;
    int ret = 0;

    g_server_thread_exit_code = 0;
    g_client_thread_exit_code = 0;
    g_server_condition = false;

    printf("test_client_fail_enclave_identity_verifier_callback_scenario\n");
    test_configs.server.enclave = g_server_enclave;
    test_configs.server.args.fail_cert_verify_callback = false;;
    test_configs.server.args.fail_enclave_identity_verifier_callback = false;
    test_configs.server.args.fail_oe_verify_tls_cert = false;

    test_configs.client.enclave = g_client_enclave;
    test_configs.client.args.fail_cert_verify_callback = false;;
    test_configs.client.args.fail_enclave_identity_verifier_callback = true;
    test_configs.client.args.fail_oe_verify_tls_cert = false;

    ret = run_test_with_config(&test_configs);
    printf("run_test_with_config returned %d\n", ret);
    return ret;
}

int test_client_fail_oe_verify_tls_cert_scenario()
{
    tls_test_configs_t test_configs;
    int ret = 0;

    g_server_thread_exit_code = 0;
    g_client_thread_exit_code = 0;
    g_server_condition = false;

    printf("test_client_fail_oe_verify_tls_cert_scenario\n");
    test_configs.server.enclave = g_server_enclave;
    test_configs.server.args.fail_cert_verify_callback = false;;
    test_configs.server.args.fail_enclave_identity_verifier_callback = false;
    test_configs.server.args.fail_oe_verify_tls_cert = false;

    test_configs.client.enclave = g_client_enclave;
    test_configs.client.args.fail_cert_verify_callback = false;;
    test_configs.client.args.fail_enclave_identity_verifier_callback = false;
    test_configs.client.args.fail_oe_verify_tls_cert = true;

    ret = run_test_with_config(&test_configs);
    printf("run_test_with_config returned %d\n", ret);
    return ret;
}

int main(int argc, const char* argv[])
{
    oe_result_t result = OE_FAILURE;
    uint32_t flags = 0;
    int ret = 0;

    if (argc != 3)
    {
        fprintf(stderr, "Usage: %s server_enc client_enc\n", argv[0]);
        goto exit;
    }

    flags = oe_get_create_flags();
    if ((result = oe_create_tls_e2e_enclave(
             argv[1], OE_ENCLAVE_TYPE_SGX, flags, NULL, 0, &g_server_enclave)) != OE_OK)
    {
        oe_put_err("oe_create_enclave(): result=%u", result);
    }

    if ((result = oe_create_tls_e2e_enclave(
             argv[2], OE_ENCLAVE_TYPE_SGX, flags, NULL, 0, &g_client_enclave)) != OE_OK)
    {
        oe_put_err("oe_create_enclave(): result=%u", result);
    }

    ret = test_normal_successful_scenario();
    OE_TEST(ret == 0);

    // negative server failure tests
    ret = test_server_fail_cert_verify_callback_scenario();
    OE_TEST(ret != 0);

    ret = test_server_fail_enclave_identity_verifier_callback_scenario();
    OE_TEST(ret != 0);

    ret = test_server_fail_oe_verify_tls_cert_scenario();
    OE_TEST(ret != 0);

    // negative client failure tests
    ret = test_client_fail_cert_verify_callback_scenario();
    OE_TEST(ret != 0);

    ret = test_client_fail_enclave_identity_verifier_callback_scenario();
    OE_TEST(ret != 0);

    ret = test_client_fail_oe_verify_tls_cert_scenario();
    OE_TEST(ret != 0);

    result = OE_OK;
exit:
    result = oe_terminate_enclave(g_client_enclave);
    OE_TEST(result == OE_OK);

    result = oe_terminate_enclave(g_server_enclave);
    OE_TEST(result == OE_OK);

    printf("=== passed all tests (tls)\n");

    return 0;
}
