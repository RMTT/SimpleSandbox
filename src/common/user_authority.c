//
// Created by mt on 7/31/18.
//


#include <unistd.h>
#include "user_authority.h"

short __user_root_authority() {
    int id = getuid();

    if (id != 0)
        return 1;
    return 0;
}
