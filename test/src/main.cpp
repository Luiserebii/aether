#define CATCH_CONFIG_MAIN
#include <catch.hpp>
#include <string.h>
#include <eth/vector-rlp-t.h>
#include <eth/rlp.h>

TEST_CASE("ETH Private Key Generation", "[meme]") {
    REQUIRE(1 == 1);

}

TEST_CASE("Testing Struct RLP_T", "[rlp_t]") {
    struct minth_rlp_t rlp;

    SECTION("0x (empty byte array)") {
        minth_rlp_t_init_from_string(&rlp, "0x");

        REQUIRE(rlp.tag == MINTH_RLP_T_BYTE_ARR);
        REQUIRE(vector_uchar_size(&rlp.value.byte_array) == 0);

        minth_rlp_t_deinit(&rlp);
    }

    SECTION("0xA291 (a valid byte array)") {
        minth_rlp_t_init_from_string(&rlp, "0xA291");
        unsigned char b[2] = {0xA2, 0x91};

        REQUIRE(rlp.tag == MINTH_RLP_T_BYTE_ARR);
        REQUIRE(vector_uchar_size(&rlp.value.byte_array) == 2);
        REQUIRE(memcmp(vector_uchar_begin(&rlp.value.byte_array), b, 2) == 0);
        
        minth_rlp_t_deinit(&rlp);
    }

    SECTION("[] (empty list)") {
        minth_rlp_t_init_from_string(&rlp, "[]");

        REQUIRE(rlp.tag == MINTH_RLP_T_LIST);
        REQUIRE(vector_rlp_t_size(&rlp.value.list) == 0);
        
        minth_rlp_t_deinit(&rlp);
    }

    SECTION("[[[]]] (nested lists)") {
        minth_rlp_t_init_from_string(&rlp, "[[[]]]");

        REQUIRE(rlp.tag == MINTH_RLP_T_LIST);
        REQUIRE(vector_rlp_t_size(&rlp.value.list) == 1);

        struct minth_rlp_t* e = vector_rlp_t_begin(&rlp.value.list);
        REQUIRE(e->tag == MINTH_RLP_T_LIST);
        REQUIRE(vector_rlp_t_size(&e->value.list) == 1);

        e = vector_rlp_t_begin(&e->value.list);
        REQUIRE(e->tag == MINTH_RLP_T_LIST);
        REQUIRE(vector_rlp_t_size(&e->value.list) == 0);
        
        minth_rlp_t_deinit(&rlp);
    }

    SECTION("[0xA393,0x5CEC20DB,0x00]") {
        minth_rlp_t_init_from_string(&rlp, "[0xA393,0x5CEC20DB,0x00]");

        REQUIRE(rlp.tag == MINTH_RLP_T_LIST);
        REQUIRE(vector_rlp_t_size(&rlp.value.list) == 3);

        unsigned char ba1[] = {0xA3, 0x93};
        struct minth_rlp_t* e = vector_rlp_t_begin(&rlp.value.list);
        REQUIRE(e->tag == MINTH_RLP_T_BYTE_ARR);
        REQUIRE(vector_uchar_size(&e->value.byte_array) == 2);
        REQUIRE(memcmp(vector_uchar_begin(&e->value.byte_array), ba1, 2) == 0);

        unsigned char ba2[] = {0x5C, 0xEC, 0x20, 0xDB};
        ++e;
        REQUIRE(e->tag == MINTH_RLP_T_BYTE_ARR);
        REQUIRE(vector_uchar_size(&e->value.byte_array) == 4);
        REQUIRE(memcmp(vector_uchar_begin(&e->value.byte_array), ba2, 4) == 0);

        unsigned char ba3[] = {0x00};
        ++e;
        REQUIRE(e->tag == MINTH_RLP_T_BYTE_ARR);
        REQUIRE(vector_uchar_size(&e->value.byte_array) == 1);
        REQUIRE(memcmp(vector_uchar_begin(&e->value.byte_array), ba3, 1) == 0);

        minth_rlp_t_deinit(&rlp);
    }

    SECTION("[0xBA95,[],[]]") {
        minth_rlp_t_init_from_string(&rlp, "[0xBA95,[],[]]");

        REQUIRE(rlp.tag == MINTH_RLP_T_LIST);
        REQUIRE(vector_rlp_t_size(&rlp.value.list) == 3);

        unsigned char b[] = {0xBA, 0x95};
        struct minth_rlp_t* e = vector_rlp_t_begin(&rlp.value.list);
        REQUIRE(e->tag == MINTH_RLP_T_BYTE_ARR);
        REQUIRE(vector_uchar_size(&e->value.byte_array) == 2);
        REQUIRE(memcmp(vector_uchar_begin(&e->value.byte_array), b, 2) == 0);

        ++e;
        REQUIRE(e->tag == MINTH_RLP_T_LIST);
        REQUIRE(vector_rlp_t_size(&e->value.list) == 0);

        ++e;
        REQUIRE(e->tag == MINTH_RLP_T_LIST);
        REQUIRE(vector_rlp_t_size(&e->value.list) == 0);
        
        minth_rlp_t_deinit(&rlp);
    }

    SECTION("[0xDA87,0xE43CAB,[],[[]]],0xFF]") {
        minth_rlp_t_init_from_string(&rlp, "[0xDA87,0xE43CABA,[],[[]],0xFF]");
        
        REQUIRE(rlp.tag == MINTH_RLP_T_LIST);
        REQUIRE(vector_rlp_t_size(&rlp.value.list) == 5);

        unsigned char ba1[] = {0xDA, 0x87};
        struct minth_rlp_t* e = vector_rlp_t_begin(&rlp.value.list);
        REQUIRE(e->tag == MINTH_RLP_T_BYTE_ARR);
        REQUIRE(vector_uchar_size(&e->value.byte_array) == 2);
        REQUIRE(memcmp(vector_uchar_begin(&e->value.byte_array), ba1, 2) == 0);

        unsigned char ba2[] = {0xE4, 0x3C, 0xAB, 0xA0};
        ++e;
        REQUIRE(e->tag == MINTH_RLP_T_BYTE_ARR);
        REQUIRE(vector_uchar_size(&e->value.byte_array) == 4);
        REQUIRE(memcmp(vector_uchar_begin(&e->value.byte_array), ba2, 4) == 0);

        ++e;
        REQUIRE(e->tag == MINTH_RLP_T_LIST);
        REQUIRE(vector_rlp_t_size(&e->value.list) == 0);
        
        ++e;
        REQUIRE(e->tag == MINTH_RLP_T_LIST);
        REQUIRE(vector_rlp_t_size(&e->value.list) == 1);

        struct minth_rlp_t* level = vector_rlp_t_begin(&e->value.list);
        REQUIRE(level->tag == MINTH_RLP_T_LIST);
        REQUIRE(vector_rlp_t_size(&level->value.list) == 0);
        
        unsigned char ba3[] = {0xFF};
        ++e;
        REQUIRE(e->tag == MINTH_RLP_T_BYTE_ARR);
        REQUIRE(vector_uchar_size(&e->value.byte_array) == 1);
        REQUIRE(memcmp(vector_uchar_begin(&e->value.byte_array), ba3, 1) == 0);
        
        minth_rlp_t_deinit(&rlp);
    }

    SECTION("[0xABCD,[0x00,[0xF388,[]],[]],0xFF]") {
        minth_rlp_t_init_from_string(&rlp, "[0xABCD,[0x00,[0xF388,[]],[]],0xFF]");

        REQUIRE(rlp.tag == MINTH_RLP_T_LIST);
        REQUIRE(vector_rlp_t_size(&rlp.value.list) == 3);

        unsigned char ba1[] = {0xAB, 0xCD};
        struct minth_rlp_t* e = vector_rlp_t_begin(&rlp.value.list);
        REQUIRE(e->tag == MINTH_RLP_T_BYTE_ARR);
        REQUIRE(vector_uchar_size(&e->value.byte_array) == 2);
        REQUIRE(memcmp(vector_uchar_begin(&e->value.byte_array), ba1, 2) == 0);

        //Advance to next piece, which is complex
        ++e;
        REQUIRE(e->tag == MINTH_RLP_T_LIST);
        REQUIRE(vector_rlp_t_size(&e->value.list) == 3);

        unsigned char ba2[] = {0x00};
        struct minth_rlp_t* e_sub1 = vector_rlp_t_begin(&e->value.list);
        REQUIRE(e_sub1->tag == MINTH_RLP_T_BYTE_ARR);
        REQUIRE(vector_uchar_size(&e_sub1->value.byte_array) == 1);
        REQUIRE(memcmp(vector_uchar_begin(&e_sub1->value.byte_array), ba2, 1) == 0);
        
        ++e_sub1;
        REQUIRE(e_sub1->tag == MINTH_RLP_T_LIST);
        REQUIRE(vector_rlp_t_size(&e_sub1->value.list) == 2);

        //ENTER SUB 2
        struct minth_rlp_t* e_sub2 = vector_rlp_t_begin(&e_sub1->value.list);
        unsigned char ba3[] = {0xF3, 0x88};
        REQUIRE(e_sub2->tag == MINTH_RLP_T_BYTE_ARR);
        REQUIRE(vector_uchar_size(&e_sub2->value.byte_array) == 2);
        REQUIRE(memcmp(vector_uchar_begin(&e_sub2->value.byte_array), ba3, 2) == 0);
        
        ++e_sub2;
        REQUIRE(e_sub2->tag == MINTH_RLP_T_LIST);
        REQUIRE(vector_rlp_t_size(&e_sub2->value.list) == 0);

        ++e_sub1;
        REQUIRE(e_sub1->tag == MINTH_RLP_T_LIST);
        REQUIRE(vector_rlp_t_size(&e_sub1->value.list) == 0);
      
        ++e;
        unsigned char ba4[] = {0xFF};
        REQUIRE(e->tag == MINTH_RLP_T_BYTE_ARR);
        REQUIRE(vector_uchar_size(&e->value.byte_array) == 1);
        REQUIRE(memcmp(vector_uchar_begin(&e->value.byte_array), ba4, 1) == 0);

        minth_rlp_t_deinit(&rlp);
    }

}
