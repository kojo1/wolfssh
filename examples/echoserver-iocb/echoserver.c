/* echoserver.c
 *
 * Copyright (C) 2014-2019 wolfSSL Inc.
 *
 * This file is part of wolfSSH.
 *
 * wolfSSH is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
 * (at your option) any later version.
 *
 * wolfSSH is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with wolfSSH.  If not, see <http://www.gnu.org/licenses/>.
 */

#define WOLFSSH_TEST_SERVER
#define WOLFSSH_TEST_ECHOSERVER


#ifdef WOLFSSL_USER_SETTINGS
    #include <wolfssl/wolfcrypt/settings.h>
#else
    #include <wolfssl/options.h>
#endif

#include <wolfssl/wolfcrypt/sha256.h>
#include <wolfssl/wolfcrypt/wc_port.h>
#include <wolfssl/wolfcrypt/ecc.h>
#include <wolfssh/ssh.h>

#include <examples/echoserver-iocb/echoserver.h>
#include <examples/echoserver-iocb/pw-key.h>
<<<<<<< Updated upstream
#include <examples/echoserver-iocb/test.h>
#include <examples/echoserver-iocb/my-iocb.h>

#define  NO_FILESYSTEM
#include <wolfssh/certs_test.h>

#if !defined(WOLFSSH_USER_IO)
      #warning "examples/echoserver-iocb/echoserver is for User IO Callback for TCP"
#endif

=======
#include <examples/echoserver-iocb/my-iocb.h>

#include <examples/echoserver-iocb/test.h>

#define  NO_FILESYSTEM
#include <wolfssh/certs_test.h>

>>>>>>> Stashed changes
#ifndef NO_WOLFSSH_SERVER

static const char echoserverBanner[] = "wolfSSH Example Echo Server\n";

#ifndef EXAMPLE_BUFFER_SZ
    #define EXAMPLE_BUFFER_SZ 4096
#endif

static byte find_char(const byte* str, const byte* buf, word32 bufSz)
{
    const byte* cur;

    while (bufSz) {
        cur = str;
        while (*cur != '\0') {
            if (*cur == *buf)
                return *cur;
            cur++;
        }
        buf++;
        bufSz--;
    }

    return 0;
}

/* handle SSH echo operations
 * returns 0 on success
 */
static int ssh_worker(WOLFSSH *ssh) {
    byte* buf = NULL;
    byte* tmpBuf;
    int bufSz, backlogSz = 0, rxSz, txSz, stop = 0, txSum;

    do {
        bufSz = EXAMPLE_BUFFER_SZ + backlogSz;

        tmpBuf = (byte*)realloc(buf, bufSz);
        if (tmpBuf == NULL)
            stop = 1;
        else
            buf = tmpBuf;

        if (!stop) {
            rxSz = wolfSSH_stream_read(ssh,
                                       buf + backlogSz,
                                       EXAMPLE_BUFFER_SZ);
            if (rxSz > 0) {
                backlogSz += rxSz;
                txSum = 0;
                txSz = 0;

                while (backlogSz != txSum && txSz >= 0 && !stop) {
                    txSz = wolfSSH_stream_send(ssh,
                                               buf + txSum,
                                               backlogSz - txSum);

                    if (txSz > 0) {
                        byte c;
                        const byte matches[] = { 0x03, 0x05, 0x06, 0x00 };

                        c = find_char(matches, buf + txSum, txSz);
                        switch (c) {
                            case 0x03:
                                stop = 1;
                                break;
                            case 0x06:
                                if (wolfSSH_TriggerKeyExchange(ssh) != WS_SUCCESS)
                                    stop = 1;
                                break;
                        }
                        txSum += txSz;
                    }
                    else if (txSz != WS_REKEYING) {
                        int error = wolfSSH_get_error(ssh);
                        if (error != WS_WANT_WRITE) {
                            stop = 1;
                        }
                        else {
                            txSz = 0;
                        }
                    }
                }

                if (txSum < backlogSz)
                    memmove(buf, buf + txSum, backlogSz - txSum);
                backlogSz -= txSum;
            }
            else {
                int error = wolfSSH_get_error(ssh);
                if (error != WS_WANT_READ)
                    stop = 1;
            }
        }
    } while (!stop);

    free(buf);
    return 0;
}


static int server_worker(WOLFSSH *ssh)
{
    int ret = 0, error = 0;
    int quit;

    ret = wolfSSH_accept(ssh);

    switch (ret) {
        case WS_SUCCESS:
            ret = ssh_worker(ssh);
            break;
        case WS_SCP_COMPLETE:
        case WS_SFTP_COMPLETE:
        default:
            err_sys("SSH accept error");
    }

    if (ret == WS_FATAL_ERROR) {
        const char* errorStr;
        error = wolfSSH_get_error(ssh);

        errorStr = wolfSSH_ErrorToName(error);

        if (error == WS_VERSION_E) {
            ret = 0; /* don't break out of loop with version miss match */
            printf("%s\n", errorStr);
        }
        else if (error == WS_USER_AUTH_E) {
            ret = 0; /* don't break out of loop with user auth error */
            printf("%s\n", errorStr);
        }
        else if (error == WS_SOCKET_ERROR_E) {
            ret = 0;
            printf("%s\n", errorStr);
        }
    }

    if (error != WS_SOCKET_ERROR_E && error != WS_FATAL_ERROR)
    {
        if (wolfSSH_shutdown(ssh) != WS_SUCCESS) {
            fprintf(stderr, "Error with SSH shutdown.\n");
        }
    }

    wolfSSH_free(ssh);

    if (ret != 0) {
        fprintf(stderr, "Error [%d] \"%s\" with handling connection.\n", ret,
                wolfSSH_ErrorToName(error));
    #ifndef WOLFSSH_NO_EXIT
        quit = 1;
    #endif
    }
    return 0;
}


#define MAX_PASSWD_RETRY 3
static int passwdRetry = MAX_PASSWD_RETRY;

static int wsUserAuth(byte authType,
                      WS_UserAuthData* authData,
                      void* ctx)
{
    PwMapList* list;
    PwMap* map;
    byte authHash[SHA256_DIGEST_SIZE];
    int ret;

    if (ctx == NULL) {
        fprintf(stderr, "wsUserAuth: ctx not set");
        return WOLFSSH_USERAUTH_FAILURE;
    }

    if (authType != WOLFSSH_USERAUTH_PASSWORD &&
        authType != WOLFSSH_USERAUTH_PUBLICKEY) {

        return WOLFSSH_USERAUTH_FAILURE;
    }

    /* Hash the password or public key with its length. */
    {
        Sha256 sha;
        byte flatSz[4];
        wc_InitSha256(&sha);
        if (authType == WOLFSSH_USERAUTH_PASSWORD) {
            c32toa(authData->sf.password.passwordSz, flatSz);
            wc_Sha256Update(&sha, flatSz, sizeof(flatSz));
            wc_Sha256Update(&sha,
                            authData->sf.password.password,
                            authData->sf.password.passwordSz);
        }
        else if (authType == WOLFSSH_USERAUTH_PUBLICKEY) {
            c32toa(authData->sf.publicKey.publicKeySz, flatSz);
            wc_Sha256Update(&sha, flatSz, sizeof(flatSz));
            wc_Sha256Update(&sha,
                            authData->sf.publicKey.publicKey,
                            authData->sf.publicKey.publicKeySz);
        }
        wc_Sha256Final(&sha, authHash);
    }

    list = (PwMapList*)ctx;
    map = list->head;

    while (map != NULL) {
        if (authData->usernameSz == map->usernameSz &&
            memcmp(authData->username, map->username, map->usernameSz) == 0) {

            if (authData->type == map->type) {
                if (memcmp(map->p, authHash, SHA256_DIGEST_SIZE) == 0) {
                    return WOLFSSH_USERAUTH_SUCCESS;
                }
                else {
                    ret = (authType == WOLFSSH_USERAUTH_PASSWORD ? 
                                (--passwdRetry > 0 ? 
                                WOLFSSH_USERAUTH_INVALID_PASSWORD : WOLFSSH_USERAUTH_REJECTED)
                                : WOLFSSH_USERAUTH_INVALID_PUBLICKEY);
                    if (passwdRetry == 0)passwdRetry = MAX_PASSWD_RETRY;
                    return ret;
                }
            }
            else {
                return WOLFSSH_USERAUTH_INVALID_AUTHTYPE;
            }
        }
        map = map->next;
    }

    return WOLFSSH_USERAUTH_INVALID_USER;
}

static void ShowUsage(void)
{
    printf("echoserver %s\n", LIBWOLFSSH_VERSION_STRING);
    printf(" -?            display this help and exit\n");
    printf(" -e            use ECC private key\n");
    printf(" -p <num>      port to connect on, default %d\n", wolfSshPort);
}

int echoserver_test(int argc, char **argv)
{
    WOLFSSH_CTX* ctx = NULL;
    PwMapList pwMapList;

    int userEcc = 0;
    int peerEcc = 0;
    int ch;
    int bufSz;
    int quit = 0;
    int port = wolfSshPort;

    if (argc > 0) {
        while ((ch = mygetopt(argc, argv, "?1d:eEp:R:N")) != -1) {
            switch (ch) {
                case '?' :
                    ShowUsage();
                    exit(EXIT_SUCCESS);

                case 'e' :
                    userEcc = 1;
                    break;

                case 'E':
                    peerEcc = 1;
                    break;

                case 'p':
                    port = (word16)atoi(myoptarg);
                    break;

                default:
                    ShowUsage();
                    exit(EXIT_FAILURE);
            }
        }
    }
    myoptind = 0;      /* reset for test cases */

    if (wolfSSH_Init() != WS_SUCCESS) {
        err_sys("Couldn't initialize wolfSSH.\n");
    }

    ctx = wolfSSH_CTX_new(WOLFSSH_ENDPOINT_SERVER, NULL);
    if (ctx == NULL) {
        err_sys("Couldn't allocate SSH CTX data.\n");
    }

    wolfSSH_SetIORecv(ctx, (WS_CallbackIORecv)my_IORecv);
    wolfSSH_SetIOSend(ctx, (WS_CallbackIOSend)my_IOSend);

    wolfSSH_SetUserAuth(ctx, wsUserAuth);
    wolfSSH_CTX_SetBanner(ctx, echoserverBanner);
    
    {
        byte buf[SCRATCH_BUFFER_SZ];
        bufSz = LoadKey(peerEcc, buf, SCRATCH_BUFFER_SZ);

        if (wolfSSH_CTX_UsePrivateKey_buffer(ctx, buf, bufSz,
                                                WOLFSSH_FORMAT_ASN1) < 0) {
            err_sys("Couldn't use key buffer.\n");
        }
    }

    LoadPw(&pwMapList, userEcc);

    do {
        SOCKET_T      sockFd = 0;
        SOCKET_T      clientFd = 0;
        SOCKADDR_IN_T addr;
        SOCKLEN_T     addrSz = sizeof(SOCKADDR_IN_T);
        WOLFSSH*      ssh;

        #ifdef USE_SOCKET
            if ((sockFd = socket(AF_INET_V, SOCK_STREAM, 0)) == 0)
                err_sys("tcp socket error");
            addr.sin_family = AF_INET;
            addr.sin_port = htons(port);
            addr.sin_addr.s_addr = INADDR_ANY;
            if (bind(sockFd, (const struct sockaddr *)&addr, addrSz) != 0)
                err_sys("tcp bind failed");
            if (listen(sockFd, 1) != 0)
                err_sys("tcp listen failed");
        #else
            /* your own TCP socket */
        #endif

        ssh = wolfSSH_new(ctx);
        if (ssh == NULL) {
            err_sys("Couldn't allocate SSH data.\n");
        }
        wolfSSH_SetUserAuthCtx(ssh, &pwMapList);

        clientFd = accept(sockFd, (struct sockaddr *)&addr, &addrSz);

        if (clientFd == -1)
            err_sys("tcp accept failed");

        wolfSSH_set_fd(ssh, (int)clientFd);

        server_worker(ssh);

    } while (!quit);

    DeletePwMapList(&pwMapList);

    wolfSSH_CTX_free(ctx);
    if (wolfSSH_Cleanup() != WS_SUCCESS) {
        err_sys("Couldn't clean up wolfSSH.\n");
    }

    return 0;
}

#endif /* NO_WOLFSSH_SERVER */


#ifndef NO_MAIN_DRIVER

    int main(int argc, char** argv)
    {
        #ifdef DEBUG_WOLFSSH
            wolfSSH_Debugging_ON();
        #endif

        echoserver_test(argc, argv);

        wolfSSH_Cleanup();

        return 0;
    }

    int myoptind = 0;
    char* myoptarg = NULL;

#endif /* NO_MAIN_DRIVER */
