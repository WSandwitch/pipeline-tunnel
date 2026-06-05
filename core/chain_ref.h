#ifndef CHAIN_REF_H
#define CHAIN_REF_H

#include <vector>

struct ChainRef {
    std::vector<int> in_fds;
    std::vector<int> out_fds;
};

#endif
