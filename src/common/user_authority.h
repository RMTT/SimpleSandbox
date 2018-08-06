//
// Created by mt on 7/31/18.
//

#ifndef IMCODER_JUDGER_USER_AUTHORITY_H
#define IMCODER_JUDGER_USER_AUTHORITY_H

/**
 * This function is used to determine whether the current is a root user
 * @return 0 or -1,0 present the user is root,otherwise is -1*/
extern int __require_root_authority();

#endif //IMCODER_JUDGER_USER_AUTHORITY_H
