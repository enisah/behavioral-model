#ifndef _BM_PIPELINE_H_
#define _BM_PIPELINE_H_

#include "control_flow.h"
#include "named_p4object.h"

class Pipeline : public NamedP4Object
{
public:
  Pipeline(const std::string &name, p4object_id_t id,
	   ControlFlowNode *first_node)
    : NamedP4Object(name, id), first_node(first_node) {}

  void apply(Packet *pkt);

  Pipeline(const Pipeline &other) = delete;
  Pipeline &operator=(const Pipeline &other) = delete;

  Pipeline(Pipeline &&other) noexcept = default;
  Pipeline &operator=(Pipeline &&other) noexcept = default;

private:
  ControlFlowNode *first_node;
};

#endif
