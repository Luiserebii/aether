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
