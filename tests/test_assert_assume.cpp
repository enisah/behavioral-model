/* Copyright 2019-Barefoot Networks, Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <gtest/gtest.h>

#include <bm/bm_sim/actions.h>
#include <bm/bm_sim/core/primitives.h>
#include <bm/bm_sim/phv.h>
#include <bm/bm_sim/parser_error.h>
#include <bm/bm_sim/packet.h>

using namespace bm;

class assert_ : public ActionPrimitive<const Data &> {
  friend class assume_;
  void operator ()(const Data &src) {
    if (src.test_eq(0)) {
      // mark paket with invalid error code
      auto error_code = ErrorCode::make_invalid();
      get_packet().set_error_code(error_code);
    }
  }
};

REGISTER_PRIMITIVE_W_NAME("assert", assert_);

class assume_ : public ActionPrimitive<const Data &> {
  void operator ()(const Data &src) {
    assert_()(src);
  }
};

REGISTER_PRIMITIVE_W_NAME("assume", assume_);

class AssertAssumeTest : public ::testing::Test {
 protected:
  ErrorCodeMap error_codes;
  PHVFactory phv_factory;
  PHV *phv{nullptr};

  ActionFn testActionFn;
  ActionFnEntry testActionFnEntry;

  std::unique_ptr<PHVSourceIface> phv_source{nullptr};
  std::unique_ptr<Packet> pkt{nullptr};

  AssertAssumeTest()
      : error_codes(ErrorCodeMap::make_with_core()),
        testActionFn("test_primitive", 0, 1),
        testActionFnEntry(&testActionFn),
        phv_source(PHVSourceIface::make_phv_source()) { }

  virtual void SetUp() {
    phv_source->set_phv_factory(0, &phv_factory);
    pkt = std::unique_ptr<Packet>(new Packet(
        Packet::make_new(phv_source.get())));
    pkt->set_error_code(error_codes.from_core(ErrorCodeMap::Core::NoError));
    phv = pkt->get_phv();
  }

  virtual void TearDown() { }

  ArithExpression* build_expression(bool value) {
    ArithExpression* condition = new ArithExpression();
    condition->push_back_load_bool(value);
    condition->push_back_op(ExprOpcode::BOOL_TO_DATA);
    condition->build();
    return condition;
  }

  void check_result(bool withError) {
    if (withError) {
      auto error_code = ErrorCode::make_invalid();
      ASSERT_EQ(error_code, pkt->get_error_code());
    } else {
      ASSERT_EQ(error_codes.from_core(ErrorCodeMap::Core::NoError),
                pkt->get_error_code());
    }
  }

  void verify_test(bool isAssert, bool withError) {
    std::unique_ptr<ActionPrimitive_> primitive;
    if (isAssert) {
      primitive = ActionOpcodesMap::get_instance()->get_primitive("assert");
    } else {
      primitive = ActionOpcodesMap::get_instance()->get_primitive("assume");
    }
    ASSERT_NE(nullptr, primitive);

    testActionFn.push_back_primitive(primitive.get());
    auto expr = build_expression(!withError);
    std::unique_ptr<ArithExpression> condition(expr);
    testActionFn.parameter_push_back_expression(std::move(condition));

    testActionFnEntry(pkt.get());

    check_result(withError);
  }
};

TEST_F(AssertAssumeTest, AssumeBoolConstError) {
  verify_test(false, true);
}

TEST_F(AssertAssumeTest, AssertBoolConstError) {
  verify_test(true, true);
}

TEST_F(AssertAssumeTest, AssumeBoolConstNoError) {
  verify_test(false, false);
}

TEST_F(AssertAssumeTest, AssertBoolConstNoError) {
  verify_test(true, false);
}
