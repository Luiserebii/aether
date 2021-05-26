#define CATCH_CONFIG_MAIN
#include <catch.hpp>
#include <string.h>
#include <aether/eth/vector-rlp-t.h>
#include <aether/eth/rlp.h>

TEST_CASE("ETH Private Key Generation", "[meme]") {
    REQUIRE(1 == 1);

}

TEST_CASE("Testing Struct RLP_T", "[rlp_t]") {
    struct aether_rlp_t rlp;

    SECTION("0x (empty byte array)") {
        aether_rlp_t_init_from_string(&rlp, "0x");

        REQUIRE(rlp.tag == AETHER_RLP_T_BYTE_ARR);
        REQUIRE(vector_uchar_size(&rlp.value.byte_array) == 0);

        aether_rlp_t_deinit(&rlp);
    }

    SECTION("0xA291 (a valid byte array)") {
        aether_rlp_t_init_from_string(&rlp, "0xA291");
        unsigned char b[2] = {0xA2, 0x91};

        REQUIRE(rlp.tag == AETHER_RLP_T_BYTE_ARR);
        REQUIRE(vector_uchar_size(&rlp.value.byte_array) == 2);
        REQUIRE(memcmp(vector_uchar_begin(&rlp.value.byte_array), b, 2) == 0);
        
        aether_rlp_t_deinit(&rlp);
    }

    SECTION("[] (empty list)") {
        aether_rlp_t_init_from_string(&rlp, "[]");

        REQUIRE(rlp.tag == AETHER_RLP_T_LIST);
        REQUIRE(vector_rlp_t_size(&rlp.value.list) == 0);
        
        aether_rlp_t_deinit(&rlp);
    }

    SECTION("[[[]]] (nested lists)") {
        aether_rlp_t_init_from_string(&rlp, "[[[]]]");

        REQUIRE(rlp.tag == AETHER_RLP_T_LIST);
        REQUIRE(vector_rlp_t_size(&rlp.value.list) == 1);

        struct aether_rlp_t* e = vector_rlp_t_begin(&rlp.value.list);
        REQUIRE(e->tag == AETHER_RLP_T_LIST);
        REQUIRE(vector_rlp_t_size(&e->value.list) == 1);

        e = vector_rlp_t_begin(&e->value.list);
        REQUIRE(e->tag == AETHER_RLP_T_LIST);
        REQUIRE(vector_rlp_t_size(&e->value.list) == 0);
        
        aether_rlp_t_deinit(&rlp);
    }

    SECTION("[0xA393,0x5CEC20DB,0x00]") {
        aether_rlp_t_init_from_string(&rlp, "[0xA393,0x5CEC20DB,0x00]");

        REQUIRE(rlp.tag == AETHER_RLP_T_LIST);
        REQUIRE(vector_rlp_t_size(&rlp.value.list) == 3);

        unsigned char ba1[] = {0xA3, 0x93};
        struct aether_rlp_t* e = vector_rlp_t_begin(&rlp.value.list);
        REQUIRE(e->tag == AETHER_RLP_T_BYTE_ARR);
        REQUIRE(vector_uchar_size(&e->value.byte_array) == 2);
        REQUIRE(memcmp(vector_uchar_begin(&e->value.byte_array), ba1, 2) == 0);

        unsigned char ba2[] = {0x5C, 0xEC, 0x20, 0xDB};
        ++e;
        REQUIRE(e->tag == AETHER_RLP_T_BYTE_ARR);
        REQUIRE(vector_uchar_size(&e->value.byte_array) == 4);
        REQUIRE(memcmp(vector_uchar_begin(&e->value.byte_array), ba2, 4) == 0);

        unsigned char ba3[] = {0x00};
        ++e;
        REQUIRE(e->tag == AETHER_RLP_T_BYTE_ARR);
        REQUIRE(vector_uchar_size(&e->value.byte_array) == 1);
        REQUIRE(memcmp(vector_uchar_begin(&e->value.byte_array), ba3, 1) == 0);

        aether_rlp_t_deinit(&rlp);
    }

    SECTION("[0xBA95,[],[]]") {
        aether_rlp_t_init_from_string(&rlp, "[0xBA95,[],[]]");

        REQUIRE(rlp.tag == AETHER_RLP_T_LIST);
        REQUIRE(vector_rlp_t_size(&rlp.value.list) == 3);

        unsigned char b[] = {0xBA, 0x95};
        struct aether_rlp_t* e = vector_rlp_t_begin(&rlp.value.list);
        REQUIRE(e->tag == AETHER_RLP_T_BYTE_ARR);
        REQUIRE(vector_uchar_size(&e->value.byte_array) == 2);
        REQUIRE(memcmp(vector_uchar_begin(&e->value.byte_array), b, 2) == 0);

        ++e;
        REQUIRE(e->tag == AETHER_RLP_T_LIST);
        REQUIRE(vector_rlp_t_size(&e->value.list) == 0);

        ++e;
        REQUIRE(e->tag == AETHER_RLP_T_LIST);
        REQUIRE(vector_rlp_t_size(&e->value.list) == 0);
        
        aether_rlp_t_deinit(&rlp);
    }

    SECTION("[0xDA87,0xE43CAB,[],[[]]],0xFF]") {
        aether_rlp_t_init_from_string(&rlp, "[0xDA87,0xE43CABA,[],[[]],0xFF]");
        
        REQUIRE(rlp.tag == AETHER_RLP_T_LIST);
        REQUIRE(vector_rlp_t_size(&rlp.value.list) == 5);

        unsigned char ba1[] = {0xDA, 0x87};
        struct aether_rlp_t* e = vector_rlp_t_begin(&rlp.value.list);
        REQUIRE(e->tag == AETHER_RLP_T_BYTE_ARR);
        REQUIRE(vector_uchar_size(&e->value.byte_array) == 2);
        REQUIRE(memcmp(vector_uchar_begin(&e->value.byte_array), ba1, 2) == 0);

        unsigned char ba2[] = {0xE4, 0x3C, 0xAB, 0xA0};
        ++e;
        REQUIRE(e->tag == AETHER_RLP_T_BYTE_ARR);
        REQUIRE(vector_uchar_size(&e->value.byte_array) == 4);
        REQUIRE(memcmp(vector_uchar_begin(&e->value.byte_array), ba2, 4) == 0);

        ++e;
        REQUIRE(e->tag == AETHER_RLP_T_LIST);
        REQUIRE(vector_rlp_t_size(&e->value.list) == 0);
        
        ++e;
        REQUIRE(e->tag == AETHER_RLP_T_LIST);
        REQUIRE(vector_rlp_t_size(&e->value.list) == 1);

        struct aether_rlp_t* level = vector_rlp_t_begin(&e->value.list);
        REQUIRE(level->tag == AETHER_RLP_T_LIST);
        REQUIRE(vector_rlp_t_size(&level->value.list) == 0);
        
        unsigned char ba3[] = {0xFF};
        ++e;
        REQUIRE(e->tag == AETHER_RLP_T_BYTE_ARR);
        REQUIRE(vector_uchar_size(&e->value.byte_array) == 1);
        REQUIRE(memcmp(vector_uchar_begin(&e->value.byte_array), ba3, 1) == 0);
        
        aether_rlp_t_deinit(&rlp);
    }

    SECTION("[0xABCD,[0x00,[0xF388,[]],[]],0xFF]") {
        aether_rlp_t_init_from_string(&rlp, "[0xABCD,[0x00,[0xF388,[]],[]],0xFF]");

        REQUIRE(rlp.tag == AETHER_RLP_T_LIST);
        REQUIRE(vector_rlp_t_size(&rlp.value.list) == 3);

        unsigned char ba1[] = {0xAB, 0xCD};
        struct aether_rlp_t* e = vector_rlp_t_begin(&rlp.value.list);
        REQUIRE(e->tag == AETHER_RLP_T_BYTE_ARR);
        REQUIRE(vector_uchar_size(&e->value.byte_array) == 2);
        REQUIRE(memcmp(vector_uchar_begin(&e->value.byte_array), ba1, 2) == 0);

        //Advance to next piece, which is complex
        ++e;
        REQUIRE(e->tag == AETHER_RLP_T_LIST);
        REQUIRE(vector_rlp_t_size(&e->value.list) == 3);

        unsigned char ba2[] = {0x00};
        struct aether_rlp_t* e_sub1 = vector_rlp_t_begin(&e->value.list);
        REQUIRE(e_sub1->tag == AETHER_RLP_T_BYTE_ARR);
        REQUIRE(vector_uchar_size(&e_sub1->value.byte_array) == 1);
        REQUIRE(memcmp(vector_uchar_begin(&e_sub1->value.byte_array), ba2, 1) == 0);
        
        ++e_sub1;
        REQUIRE(e_sub1->tag == AETHER_RLP_T_LIST);
        REQUIRE(vector_rlp_t_size(&e_sub1->value.list) == 2);

        //ENTER SUB 2
        struct aether_rlp_t* e_sub2 = vector_rlp_t_begin(&e_sub1->value.list);
        unsigned char ba3[] = {0xF3, 0x88};
        REQUIRE(e_sub2->tag == AETHER_RLP_T_BYTE_ARR);
        REQUIRE(vector_uchar_size(&e_sub2->value.byte_array) == 2);
        REQUIRE(memcmp(vector_uchar_begin(&e_sub2->value.byte_array), ba3, 2) == 0);
        
        ++e_sub2;
        REQUIRE(e_sub2->tag == AETHER_RLP_T_LIST);
        REQUIRE(vector_rlp_t_size(&e_sub2->value.list) == 0);

        ++e_sub1;
        REQUIRE(e_sub1->tag == AETHER_RLP_T_LIST);
        REQUIRE(vector_rlp_t_size(&e_sub1->value.list) == 0);
      
        ++e;
        unsigned char ba4[] = {0xFF};
        REQUIRE(e->tag == AETHER_RLP_T_BYTE_ARR);
        REQUIRE(vector_uchar_size(&e->value.byte_array) == 1);
        REQUIRE(memcmp(vector_uchar_begin(&e->value.byte_array), ba4, 1) == 0);

        aether_rlp_t_deinit(&rlp);
    }

}


TEST_CASE("Testing RLP Encoding", "[rlp_encoding]") {
    struct aether_rlp_t rlp;
    vector_uchar encoding;

    SECTION("0x0") {
        aether_rlp_t_init_from_string(&rlp, "0x0");
        vector_uchar_init(&encoding);
        aether_rlp_t_encode(&rlp, &encoding);

        unsigned char e[] = {0x0};

        REQUIRE(vector_uchar_size(&encoding) == 1);
        REQUIRE(memcmp(vector_uchar_begin(&encoding), e, 1) == 0);

        aether_rlp_t_deinit(&rlp);
        vector_uchar_deinit(&encoding);
    }

    SECTION("0x1F") {
        aether_rlp_t_init_from_string(&rlp, "0x1F");
        vector_uchar_init(&encoding);
        aether_rlp_t_encode(&rlp, &encoding);
        
        unsigned char e[] = {0x1F};

        REQUIRE(vector_uchar_size(&encoding) == 1);
        REQUIRE(memcmp(vector_uchar_begin(&encoding), e, 1) == 0);

        aether_rlp_t_deinit(&rlp);
        vector_uchar_deinit(&encoding);
    }

    SECTION("0x7F") {
        //Test 127 
        aether_rlp_t_init_from_string(&rlp, "0x7F");
        vector_uchar_init(&encoding);
        aether_rlp_t_encode(&rlp, &encoding);

        unsigned char e[] = {0x7F};

        REQUIRE(vector_uchar_size(&encoding) == 1);
        REQUIRE(memcmp(vector_uchar_begin(&encoding), e, 1) == 0);

        aether_rlp_t_deinit(&rlp);
        vector_uchar_deinit(&encoding);
    }

    SECTION("0x80") {
        //Test 128
        aether_rlp_t_init_from_string(&rlp, "0x80");
        vector_uchar_init(&encoding);
        aether_rlp_t_encode(&rlp, &encoding);

        unsigned char e[] = {0x81, 0x80};

        REQUIRE(vector_uchar_size(&encoding) == 2);
        REQUIRE(memcmp(vector_uchar_begin(&encoding), e, 2) == 0);

        aether_rlp_t_deinit(&rlp);
        vector_uchar_deinit(&encoding);
    }

    SECTION("0x1AF24828FC382D1A") {
        //Testing arbitrary longer length, less than 56 bytes
        aether_rlp_t_init_from_string(&rlp, "0x1AF24828FC382D1A");
        vector_uchar_init(&encoding);
        aether_rlp_t_encode(&rlp, &encoding);

        unsigned char e[] = {0x88, 0x1A, 0xF2, 0x48, 0x28, 0xFC, 0x38, 0x2D, 0x1A};

        REQUIRE(vector_uchar_size(&encoding) == sizeof(e));
        REQUIRE(memcmp(vector_uchar_begin(&encoding), e, sizeof(e)) == 0);

        aether_rlp_t_deinit(&rlp);
        vector_uchar_deinit(&encoding);
    }

    SECTION("0x9C72B3D3C75A564E8938D4C2C6802391F66F44703F39B36F24D2653EF096BA7B03EDFCCC045772C69236A6DE57E731C4465F4EBA02AFAE") {
        //Testing 55 bytes, right underneath range requirement of 56 bytes
        aether_rlp_t_init_from_string(&rlp, "0x9C72B3D3C75A564E8938D4C2C6802391F66F44703F39B36F24D2653EF096BA7B03EDFCCC045772C69236A6DE57E731C4465F4EBA02AFAE");
        vector_uchar_init(&encoding);
        aether_rlp_t_encode(&rlp, &encoding);

        unsigned char e[] = {0xB7, 0x9C, 0x72, 0xB3, 0xD3, 0xC7, 0x5A, 0x56, 0x4E, 0x89, 0x38, 0xD4, 0xC2, 0xC6, 0x80, 0x23, 0x91, 0xF6, 0x6F, 0x44, 0x70, 0x3F, 0x39, 0xB3, 0x6F, 0x24, 0xD2, 0x65, 0x3E, 0xF0, 0x96, 0xBA, 0x7B, 0x03, 0xED, 0xFC, 0xCC, 0x04, 0x57, 0x72, 0xC6, 0x92, 0x36, 0xA6, 0xDE, 0x57, 0xE7, 0x31, 0xC4, 0x46, 0x5F, 0x4E, 0xBA, 0x02, 0xAF, 0xAE};

        REQUIRE(sizeof(e) == 55 + 1);
        REQUIRE(vector_uchar_size(&encoding) == sizeof(e));
        REQUIRE(memcmp(vector_uchar_begin(&encoding), e, sizeof(e)) == 0);

        aether_rlp_t_deinit(&rlp);
        vector_uchar_deinit(&encoding);
    }

    SECTION("0xDE0246F619748D5DC39064B8B885008FDAC112B30F411021A064E20FF064CB109BD57AA810B6ABE8A9A874B798D02122930645519479AEB5") {
        //Testing 56 bytes, right over range requirement of 56 bytes
        aether_rlp_t_init_from_string(&rlp, "0xDE0246F619748D5DC39064B8B885008FDAC112B30F411021A064E20FF064CB109BD57AA810B6ABE8A9A874B798D02122930645519479AEB5");
        vector_uchar_init(&encoding);
        aether_rlp_t_encode(&rlp, &encoding);

        unsigned char e[] = {0xB8, 0x38, 0xDE, 0x02, 0x46, 0xF6, 0x19, 0x74, 0x8D, 0x5D, 0xC3, 0x90, 0x64, 0xB8, 0xB8, 0x85, 0x00, 0x8F, 0xDA, 0xC1, 0x12, 0xB3, 0x0F, 0x41, 0x10, 0x21, 0xA0, 0x64, 0xE2, 0x0F, 0xF0, 0x64, 0xCB, 0x10, 0x9B, 0xD5, 0x7A, 0xA8, 0x10, 0xB6, 0xAB, 0xE8, 0xA9, 0xA8, 0x74, 0xB7, 0x98, 0xD0, 0x21, 0x22, 0x93, 0x06, 0x45, 0x51, 0x94, 0x79, 0xAE, 0xB5};

        REQUIRE(sizeof(e) == 56 + 2);
        REQUIRE(vector_uchar_size(&encoding) == sizeof(e));
        REQUIRE(memcmp(vector_uchar_begin(&encoding), e, sizeof(e)) == 0);

        aether_rlp_t_deinit(&rlp);
        vector_uchar_deinit(&encoding);
    }
    
    SECTION("0x0FA7CA379CAA1918156E6992D7923D9A77BF7CDA9E2508A261E76F5E1DC65D748ADE2BDD848F96ADDD600562E3BE66D06F0C4A1CB4D4E7A408BC666117DF6CCAA7D3F540CCAF226CF7E665B857A817DEFDC7C534D2301D57CAF902060227D81B1227EC052661AEA2B13152F7076F3A319ECD89F814CC91C08B1887A9AAA59D8B5E4CC74CE8DB3135342605D7815AFF67BB5D95C44A404C0A6A1879F2C12FF7D40AE5FE79B81FAE3D382B64F3C885BC2B4F90BC299CFBF821060E9852FD916C1FD43374B90F296CB5B5EF3016380470E21A9B7B10FBF941A19F23311C1099E8AD2001ACD01596AEDFB22D9F2B022A31D1FC5BE86AC42ED422C8483623DA256118") {
        //Testing arbitrary number over range requirement of 56 bytes
        aether_rlp_t_init_from_string(&rlp, "0x0FA7CA379CAA1918156E6992D7923D9A77BF7CDA9E2508A261E76F5E1DC65D748ADE2BDD848F96ADDD600562E3BE66D06F0C4A1CB4D4E7A408BC666117DF6CCAA7D3F540CCAF226CF7E665B857A817DEFDC7C534D2301D57CAF902060227D81B1227EC052661AEA2B13152F7076F3A319ECD89F814CC91C08B1887A9AAA59D8B5E4CC74CE8DB3135342605D7815AFF67BB5D95C44A404C0A6A1879F2C12FF7D40AE5FE79B81FAE3D382B64F3C885BC2B4F90BC299CFBF821060E9852FD916C1FD43374B90F296CB5B5EF3016380470E21A9B7B10FBF941A19F23311C1099E8AD2001ACD01596AEDFB22D9F2B022A31D1FC5BE86AC42ED422C8483623DA256118");
        vector_uchar_init(&encoding);
        aether_rlp_t_encode(&rlp, &encoding);

        unsigned char e[] = {0xB9, 0x01, 0x00, 0x0F, 0xA7, 0xCA, 0x37, 0x9C, 0xAA, 0x19, 0x18, 0x15, 0x6E, 0x69, 0x92, 0xD7, 0x92, 0x3D, 0x9A, 0x77, 0xBF, 0x7C, 0xDA, 0x9E, 0x25, 0x08, 0xA2, 0x61, 0xE7, 0x6F, 0x5E, 0x1D, 0xC6, 0x5D, 0x74, 0x8A, 0xDE, 0x2B, 0xDD, 0x84, 0x8F, 0x96, 0xAD, 0xDD, 0x60, 0x05, 0x62, 0xE3, 0xBE, 0x66, 0xD0, 0x6F, 0x0C, 0x4A, 0x1C, 0xB4, 0xD4, 0xE7, 0xA4, 0x08, 0xBC, 0x66, 0x61, 0x17, 0xDF, 0x6C, 0xCA, 0xA7, 0xD3, 0xF5, 0x40, 0xCC, 0xAF, 0x22, 0x6C, 0xF7, 0xE6, 0x65, 0xB8, 0x57, 0xA8, 0x17, 0xDE, 0xFD, 0xC7, 0xC5, 0x34, 0xD2, 0x30, 0x1D, 0x57, 0xCA, 0xF9, 0x02, 0x06, 0x02, 0x27, 0xD8, 0x1B, 0x12, 0x27, 0xEC, 0x05, 0x26, 0x61, 0xAE, 0xA2, 0xB1, 0x31, 0x52, 0xF7, 0x07, 0x6F, 0x3A, 0x31, 0x9E, 0xCD, 0x89, 0xF8, 0x14, 0xCC, 0x91, 0xC0, 0x8B, 0x18, 0x87, 0xA9, 0xAA, 0xA5, 0x9D, 0x8B, 0x5E, 0x4C, 0xC7, 0x4C, 0xE8, 0xDB, 0x31, 0x35, 0x34, 0x26, 0x05, 0xD7, 0x81, 0x5A, 0xFF, 0x67, 0xBB, 0x5D, 0x95, 0xC4, 0x4A, 0x40, 0x4C, 0x0A, 0x6A, 0x18, 0x79, 0xF2, 0xC1, 0x2F, 0xF7, 0xD4, 0x0A, 0xE5, 0xFE, 0x79, 0xB8, 0x1F, 0xAE, 0x3D, 0x38, 0x2B, 0x64, 0xF3, 0xC8, 0x85, 0xBC, 0x2B, 0x4F, 0x90, 0xBC, 0x29, 0x9C, 0xFB, 0xF8, 0x21, 0x06, 0x0E, 0x98, 0x52, 0xFD, 0x91, 0x6C, 0x1F, 0xD4, 0x33, 0x74, 0xB9, 0x0F, 0x29, 0x6C, 0xB5, 0xB5, 0xEF, 0x30, 0x16, 0x38, 0x04, 0x70, 0xE2, 0x1A, 0x9B, 0x7B, 0x10, 0xFB, 0xF9, 0x41, 0xA1, 0x9F, 0x23, 0x31, 0x1C, 0x10, 0x99, 0xE8, 0xAD, 0x20, 0x01, 0xAC, 0xD0, 0x15, 0x96, 0xAE, 0xDF, 0xB2, 0x2D, 0x9F, 0x2B, 0x02, 0x2A, 0x31, 0xD1, 0xFC, 0x5B, 0xE8, 0x6A, 0xC4, 0x2E, 0xD4, 0x22, 0xC8, 0x48, 0x36, 0x23, 0xDA, 0x25, 0x61, 0x18};

        REQUIRE(vector_uchar_size(&encoding) == sizeof(e));
        REQUIRE(memcmp(vector_uchar_begin(&encoding), e, sizeof(e)) == 0);

        aether_rlp_t_deinit(&rlp);
        vector_uchar_deinit(&encoding);
    }

/**
 * 0x80 | 0x8180
 * 0x1AF24828FC382D1A | 0x881AF24828FC382D1A
 *
 * 0x9C72B3D3C75A564E8938D4C2C6802391F66F44703F39B36F24D2653EF096BA7B03EDFCCC045772C69236A6DE57E731C4465F4EBA02AFAE | 0xB79C72B3D3C75A564E8938D4C2C6802391F66F44703F39B36F24D2653EF096BA7B03EDFCCC045772C69236A6DE57E731C4465F4EBA02AFAE
 *
 * 0xDE0246F619748D5DC39064B8B885008FDAC112B30F411021A064E20FF064CB109BD57AA810B6ABE8A9A874B798D02122930645519479AEB5 | 0xB838DE0246F619748D5DC39064B8B885008FDAC112B30F411021A064E20FF064CB109BD57AA810B6ABE8A9A874B798D02122930645519479AEB5
 * 
 * 0FA7CA379CAA1918156E6992D7923D9A77BF7CDA9E2508A261E76F5E1DC65D748ADE2BDD848F96ADDD600562E3BE66D06F0C4A1CB4D4E7A408BC666117DF6CCAA7D3F540CCAF226CF7E665B857A817DEFDC7C534D2301D57CAF902060227D81B1227EC052661AEA2B13152F7076F3A319ECD89F814CC91C08B1887A9AAA59D8B5E4CC74CE8DB3135342605D7815AFF67BB5D95C44A404C0A6A1879F2C12FF7D40AE5FE79B81FAE3D382B64F3C885BC2B4F90BC299CFBF821060E9852FD916C1FD43374B90F296CB5B5EF3016380470E21A9B7B10FBF941A19F23311C1099E8AD2001ACD01596AEDFB22D9F2B022A31D1FC5BE86AC42ED422C8483623DA256118 | 0xB901000FA7CA379CAA1918156E6992D7923D9A77BF7CDA9E2508A261E76F5E1DC65D748ADE2BDD848F96ADDD600562E3BE66D06F0C4A1CB4D4E7A408BC666117DF6CCAA7D3F540CCAF226CF7E665B857A817DEFDC7C534D2301D57CAF902060227D81B1227EC052661AEA2B13152F7076F3A319ECD89F814CC91C08B1887A9AAA59D8B5E4CC74CE8DB3135342605D7815AFF67BB5D95C44A404C0A6A1879F2C12FF7D40AE5FE79B81FAE3D382B64F3C885BC2B4F90BC299CFBF821060E9852FD916C1FD43374B90F296CB5B5EF3016380470E21A9B7B10FBF941A19F23311C1099E8AD2001ACD01596AEDFB22D9F2B022A31D1FC5BE86AC42ED422C8483623DA256118
 *
 */

}
