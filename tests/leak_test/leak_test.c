/* Host-side regression test for the CTAPHID stack leak (issue #10).
 *
 * Fidelio used to answer unknown commands, oversized init packets, CBOR
 * failures and U2F GET_VERSION with 64-byte HID reports whose tail was
 * uninitialised stack. This test compiles the real src/u2f.c with the
 * pico/wolfssl layer stubbed out, drives parse_u2fhid_packet() through
 * every one of those paths, and asserts the captured frame byte-for-byte:
 *
 *   unknown command   -> [CID, 0xBF, 0x0001, 0x01, 0x00 x59]  INVALID_CMD
 *   oversized length  -> [CID, 0xBF, 0x0001, 0x03, 0x00 x59]  INVALID_LEN
 *   CBOR failure      -> [CID, 0xBF, 0x0001, 0x7F, 0x00 x59]  OTHER
 *   U2F GET_VERSION   -> [CID, 0x83, 0x0008, "U2F_V2", 0x9000, 0x00 x55]
 *
 * A 0xA5 canary is kept on the stack of the calling function: if any path
 * ever transmits raw stack again, the canary bytes show up in the frame.
 *
 *   make -C tests/leak_test run
 */
#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>

int parse_u2fhid_packet(const uint8_t *data);
void tud_hid_report_complete_cb(uint8_t instance, uint8_t const *report,
                                uint8_t len);

extern int frame_count;
extern uint8_t frames[][64];
extern int stub_ctap2_fail;
extern int stub_ctap2_reply_len;

#define CANARY 0xA5
#define CID_TEST 0x12345678U

static int failures = 0;

static void build_init_packet(uint8_t *pkt, uint32_t cid, uint8_t cmd,
                              uint16_t len, const uint8_t *data)
{
    memset(pkt, 0, 64);
    pkt[0] = (uint8_t)(cid & 0xFFU);
    pkt[1] = (uint8_t)((cid >> 8) & 0xFFU);
    pkt[2] = (uint8_t)((cid >> 16) & 0xFFU);
    pkt[3] = (uint8_t)((cid >> 24) & 0xFFU);
    pkt[4] = 0x80 | cmd;
    pkt[5] = (uint8_t)(len >> 8);
    pkt[6] = (uint8_t)(len & 0xFFU);
    if (data)
        memcpy(pkt + 7, data, len > 57 ? 57 : len);
}

static void check_frame(const char *name, const uint8_t *expected)
{
    int i;
    int canary_leak = 0;

    if (frame_count != 1) {
        printf("FAIL %s: expected 1 HID frame, got %d\n", name, frame_count);
        failures++;
        return;
    }
    for (i = 0; i < 64; i++) {
        if (frames[0][i] == CANARY)
            canary_leak = 1;
        if (frames[0][i] != expected[i]) {
            printf("FAIL %s: frame mismatch at byte %d\n", name, i);
            printf("  got     : ");
            for (int j = 0; j < 64; j++)
                printf("%02X", frames[0][j]);
            printf("\n  expected: ");
            for (int j = 0; j < 64; j++)
                printf("%02X", expected[j]);
            printf("\n");
            failures++;
            return;
        }
    }
    if (canary_leak) {
        printf("FAIL %s: canary bytes in frame (raw stack transmitted)\n",
               name);
        failures++;
        return;
    }
    printf("PASS %s\n", name);
}

/* The canary sits on this function's stack, in the same frame region the
 * old uninitialised reply[64] locals lived in. */
static void settle_frames(void)
{
    int i;

    for (i = 0; i < frame_count; i++)
        tud_hid_report_complete_cb(0, NULL, 64);
}

static void run_case(const char *name, uint32_t cid, uint8_t cmd,
                     uint16_t len, const uint8_t *data,
                     const uint8_t *expected)
{
    uint8_t pkt[64];
    uint8_t canary[512];

    memset(canary, CANARY, sizeof(canary));
    build_init_packet(pkt, cid, cmd, len, data);
    frame_count = 0;
    parse_u2fhid_packet(pkt);
    settle_frames();
    check_frame(name, expected);
}

int main(void)
{
    uint8_t expected[64];
    uint8_t expected_err_inflight[8] = { 0x03, 0x00, 0x00, 0x00,
                                         0xBF, 0x00, 0x01, 0x01 };
    uint32_t cid_test = CID_TEST;
    uint8_t u2f_ver[8] = { 0x00, 0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
    uint8_t cbor[8] = { 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08 };

    /* 1. Unknown CTAPHID command: INVALID_CMD (0x01). */
    memset(expected, 0, sizeof(expected));
    memcpy(expected, &cid_test, 4);
    expected[4] = 0xBF;
    expected[6] = 1;
    expected[7] = 0x01;
    run_case("unknown cmd 0x30 -> INVALID_CMD", CID_TEST, 0x30, 0, NULL,
             expected);

    /* 2. Oversized init packet: INVALID_LEN (0x03). */
    memset(expected, 0, sizeof(expected));
    expected[0] = 0x21; expected[1] = 0x43; expected[2] = 0x65;
    expected[3] = 0x87;
    expected[4] = 0xBF;
    expected[6] = 1;
    expected[7] = 0x03;
    run_case("oversized len 8000 -> INVALID_LEN", 0x87654321U, 0x01, 8000,
             NULL, expected);

    /* 3. CBOR request that fails: OTHER (0x7F). */
    memset(expected, 0, sizeof(expected));
    expected[0] = 0xDD; expected[1] = 0xCC; expected[2] = 0xBB;
    expected[3] = 0xAA;
    expected[4] = 0xBF;
    expected[6] = 1;
    expected[7] = 0x7F;
    run_case("CBOR failure -> OTHER", 0xAABBCCDDU, 0x10, 8, cbor, expected);

    /* 4. U2F GET_VERSION: zero-padded frame, caller CID, "U2F_V2" + 0x9000. */
    memset(expected, 0, sizeof(expected));
    expected[0] = 0x01;
    expected[4] = 0x83;
    expected[6] = 8;
    memcpy(expected + 7, "U2F_V2", 6);
    expected[13] = 0x90;
    expected[14] = 0x00;
    run_case("U2F GET_VERSION -> U2F_V2 + 0x9000", 0x00000001U, 0x03, 8,
             u2f_ver, expected);

    /* 5. Unknown command arriving while a multi-frame reply is in flight:
     * the error frame must not be followed by stale continuation frames. */
    {
        uint8_t pkt[64];
        uint8_t cbor[8] = { 0x42, 0, 0, 0, 0, 0, 0, 0 };
        int in_flight = 0;

        stub_ctap2_fail = 0;
        stub_ctap2_reply_len = 200; /* 4 CTAPHID frames */
        build_init_packet(pkt, 0x00000002U, 0x10, 8, cbor);
        frame_count = 0;
        parse_u2fhid_packet(pkt);
        /* Reply in flight: first frame sent, continuation pending. */
        in_flight = (frame_count == 1);
        build_init_packet(pkt, 0x00000003U, 0x30, 0, NULL);
        parse_u2fhid_packet(pkt);
        settle_frames();
        stub_ctap2_fail = 1;
        if (!in_flight || frame_count != 2) {
            printf("FAIL in-flight error: expected 2 frames, got %d\n",
                   frame_count);
            failures++;
        } else if (memcmp(frames[1], expected_err_inflight, 8) != 0) {
            printf("FAIL in-flight error: second frame is not the error\n");
            failures++;
        } else {
            printf("PASS in-flight error -> no stale continuation frames\n");
        }
    }

    /* A completed request must not be executed again by a stray continuation. */
    {
        uint8_t pkt[64] = {0};
        build_init_packet(pkt, CID_TEST, 0x03, 8, u2f_ver);
        frame_count = 0;
        parse_u2fhid_packet(pkt);
        memset(pkt, 0, sizeof(pkt));
        memcpy(pkt, &cid_test, 4);
        parse_u2fhid_packet(pkt);
        if (frame_count != 1) {
            printf("FAIL completed request replay: %d frames\n", frame_count);
            failures++;
        } else {
            printf("PASS completed request retired\n");
        }
    }

    /* Continuation replies must carry the request CID. */
    {
        uint8_t pkt[64];
        stub_ctap2_fail = 0;
        stub_ctap2_reply_len = 100;
        build_init_packet(pkt, CID_TEST, 0x10, 8, cbor);
        frame_count = 0;
        parse_u2fhid_packet(pkt);
        tud_hid_report_complete_cb(0, NULL, 64);
        if (frame_count != 2 || memcmp(frames[1], &cid_test, 4) != 0) {
            printf("FAIL reply continuation CID\n");
            failures++;
        } else {
            printf("PASS reply continuation CID\n");
        }
        stub_ctap2_fail = 1;
    }

    /* Another channel cannot complete a pending request. */
    {
        uint8_t pkt[64];
        uint8_t tail[64] = {0};
        uint8_t long_version[57] = { 0x00, 0x03 };
        uint32_t other_cid = CID_TEST + 1;
        build_init_packet(pkt, CID_TEST, 0x03, 60, long_version);
        frame_count = 0;
        parse_u2fhid_packet(pkt);
        memcpy(tail, &other_cid, 4);
        parse_u2fhid_packet(tail);
        if (frame_count != 0) {
            printf("FAIL foreign continuation completed request\n");
            failures++;
        } else {
            printf("PASS foreign continuation ignored\n");
        }
    }

    if (failures) {
        printf("\n%d FAILURE(S)\n", failures);
        return 1;
    }
    printf("\nAll leak tests passed.\n");
    return 0;
}
