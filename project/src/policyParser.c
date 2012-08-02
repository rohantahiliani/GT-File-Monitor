#include <libxml2/libxml/parser.h>
#include <libxml2/libxml/tree.h>
#include "commonHeaders.h"
#include "accessPolicy.h"
#include "accessMode.h"


static const char *policyTagName = "Policy";
static const char *groupTagName = "Group";
static const char *idAttributeName = "ID";
static const char *accessTagName = "Access";
static const char *allowTagName = "Allow";
static const char *fileTagName = "file";
static const char *nameAttributeName = "name";
static const char *modeAttributeName = "mode";
static const char *userTagName = "User";
static const char *denyTagName = "Deny";
static const char *permissionsTagName = "Permissions";
void freePolicyList(aclList ptr);

static policyPtr getNewPolicyElement() {
    policyPtr newNode = null;
    newNode = (policyPtr) malloc(sizeof (policyNode));
    newNode->allow = 0;
    newNode->fileName = null;
    newNode->groups = null;
    newNode->next = null;
    newNode->users = null;
    newNode->noOfGroups = 0;
    newNode->noOfUsers = 0;
    newNode->mode = 0;
    return newNode;
}

static aclList getNewPolicyList() {
    aclList ptr = null;
    ptr = (aclList) malloc(sizeof (accessListNode));
    ptr->count = 0;
    ptr->front = null;
    ptr->last = null;
    return ptr;
}

static void freePolicyElement(policyPtr element) {
    if (element) {
        long i = 0;
        free(element->fileName);
        element->next = null;
        i = element->noOfGroups - 1;
        while (i >= 0) {
            free(element->groups[i--]);
        }
        if (element->groups) {
            free(element->groups);
        }
        i = element->noOfUsers - 1;
        while (i >= 0) {
            free(element->users[i--]);
        }
        if (element->users) {
            free(element->users);
        }
        free(element);
    }
}

void freePolicyList(aclList ptr) {
    if (ptr) {
        long i = ptr->count;
        policyPtr next = null;
        policyPtr curr = ptr->front;
        while (i > 0 && curr) {
            next = curr->next;
            freePolicyElement(curr);
            curr=next;
            i--;
        }
        free(ptr);
    }
}

static void insertAtStart(aclList ptr, policyPtr node) {
    if (ptr && node) {
        ptr->count++;
        if (ptr->front) {
            node->next = ptr->front;
            ptr->front = node;
        } else {
            ptr->front = ptr->last = node;
            node->next = null;
        }
    }
}

static void insertAtBack(aclList ptr, policyPtr node) {
    if (ptr && node) {
        ptr->count++;
        if (ptr->last) {
            node->next = null;
            ptr->last->next = node;
            ptr->last = node;
        } else {
            ptr->front = ptr->last = node;
            node->next = null;
        }
    }
}

static char* parseFile(xmlNode *node) {
    xmlNode *cur_node = node;
    char *retVal = null;
    retVal = null;
    if (cur_node && cur_node->type == XML_ELEMENT_NODE && !strcmp(cur_node->name, fileTagName)) {
        char *fileName = xmlGetProp(cur_node, nameAttributeName);
        if (!fileName) {
            goto cleanup;
        }
        retVal = (char*) malloc(sizeof (char) * (strlen(fileName) + 1));
        strcpy(retVal, fileName);
        for (cur_node = node->children; cur_node; cur_node = cur_node->next) {
            if (cur_node->type == XML_ELEMENT_NODE) {
                fprintf(stderr, "\nInvalid Element:%s\n", cur_node->name);
                goto cleanup;
            }
        }
    } else {
        fprintf(stderr, "Expected element : %s, as root node but found:%s", fileTagName, cur_node->name);
    }

ret:
    return retVal;
cleanup:
    if (retVal) {
        free(retVal);
        retVal = null;
    }
    goto ret;
}

static long parseAccess(xmlNode *node) {
    xmlNode *cur_node = node;
    long retVal = -1;
    ulong i = 0;
    if (cur_node && cur_node->type == XML_ELEMENT_NODE && !strcmp(cur_node->name, accessTagName)) {
        char *perms = xmlGetProp(cur_node, modeAttributeName);
        if (!perms) {
            goto cleanup;
        }
        retVal = 0;
        for (i = 0; i < strlen(perms); i++) {
            if (perms[i] == 'r' || perms[i] == 'R') {
                retVal |= READ;
            } else if (perms[i] == 'w' || perms[i] == 'W') {
                retVal |= WRITE;
            } else if (perms[i] == 'x' || perms[i] == 'X') {
                retVal |= EXECUTE;
            } else {
                goto cleanup;
            }
        }
        for (cur_node = node->children; cur_node; cur_node = cur_node->next) {
            if (cur_node->type == XML_ELEMENT_NODE) {
                fprintf(stderr, "\nInvalid Element:%s\n", cur_node->name);
                goto cleanup;
            }
        }
    } else {
        fprintf(stderr, "Expected element : %s, as root node but found:%s", accessTagName, cur_node->name);
    }
ret:
    return retVal;
cleanup:
    retVal = -1;
    goto ret;
}

static char* parseUser(xmlNode *node) {
    xmlNode *cur_node = node;
    char *retVal = null;
    retVal = null;
    if (cur_node && cur_node->type == XML_ELEMENT_NODE && !strcmp(cur_node->name, userTagName)) {
        char *userName = xmlGetProp(cur_node, nameAttributeName);
        if (!userName) {
            goto cleanup;
        }
        retVal = (char*) malloc(sizeof (char) * (strlen(userName) + 1));
        strcpy(retVal, userName);
        for (cur_node = node->children; cur_node; cur_node = cur_node->next) {
            if (cur_node->type == XML_ELEMENT_NODE) {
                fprintf(stderr, "\nInvalid Element:%s\n", cur_node->name);
                goto cleanup;
            }

        }
    } else {
        fprintf(stderr, "Expected element : %s, as root node but found:%s", userTagName, cur_node->name);
    }
ret:
    return retVal;
cleanup:
    if (retVal) {
        free(retVal);
        retVal = null;
    }
    goto ret;
}

static char* parseGroup(xmlNode *node) {
    xmlNode *cur_node = node;
    char *retVal = null;
    retVal = null;
    if (cur_node && cur_node->type == XML_ELEMENT_NODE && !strcmp(cur_node->name, groupTagName)) {
        char *id = xmlGetProp(cur_node, "ID");
        if (!id) {
            goto cleanup;
        }
        retVal = (char*) malloc(sizeof (char) * (strlen(id) + 1));
        strcpy(retVal, id);
        for (cur_node = node->children; cur_node; cur_node = cur_node->next) {
            if (cur_node->type == XML_ELEMENT_NODE) {
                fprintf(stderr, "\nInvalid Element:%s\n", cur_node->name);
                goto cleanup;
            }

        }

    } else {
        fprintf(stderr, "Expected element : %s, as root node but found:%s", groupTagName, cur_node->name);
    }
ret:
    return retVal;
cleanup:
    if (retVal) {
        free(retVal);
        retVal = null;
    }
    goto ret;
}

static ulong getNoOfUsers(xmlNode *node) {
    xmlNode *cur_node = node;
    ulong noOfUsers = 0;
    for (cur_node = node->children; cur_node; cur_node = cur_node->next) {
        if (cur_node->type == XML_ELEMENT_NODE) {
            if (!strcmp(cur_node->name, userTagName)) {
                noOfUsers++;
            }
        }
    }
    return noOfUsers;
}

static ulong getNoOfGroups(xmlNode *node) {
    xmlNode *cur_node = node;
    ulong noOfGroups = 0;
    for (cur_node = node->children; cur_node; cur_node = cur_node->next) {
        if (cur_node->type == XML_ELEMENT_NODE) {
            if (!strcmp(cur_node->name, groupTagName)) {
                noOfGroups++;
            }
        }
    }
    return noOfGroups;
}

static policyPtr parsePermission(xmlNode *node, int allow) {
    xmlNode *cur_node = node;
    int accessParsed = 0;
    ulong noOfGroups = 0;
    ulong noOfUsers = 0;
    int fileParsed = 0;
    ulong userIndex = 0;
    ulong groupIndex = 0;
    long tempaccessMode = 0;
    policyPtr newAccessNode = null;
    char *temp = null;
    if (cur_node && cur_node->type == XML_ELEMENT_NODE && (!strcmp(cur_node->name, allowTagName) || !strcmp(cur_node->name, denyTagName))) {
        fileParsed = 0;
        accessParsed = 0;
        noOfGroups = getNoOfGroups(cur_node);
        noOfUsers = getNoOfUsers(cur_node);
        newAccessNode = getNewPolicyElement();
        if (noOfGroups) {
            newAccessNode->groups = (char**) malloc(sizeof (char*) * noOfGroups);
        }
        if (noOfUsers) {
            newAccessNode->users = (char**) malloc(sizeof (char*) * noOfUsers);
        }
        newAccessNode->allow = allow;
        userIndex = 0;
        groupIndex = 0;
        tempaccessMode = -1;
        for (cur_node = node->children; cur_node; cur_node = cur_node->next) {
            if (cur_node->type == XML_ELEMENT_NODE) {
                if (!strcmp(cur_node->name, fileTagName) && !(fileParsed)) {
                    temp = parseFile(cur_node);
                    fileParsed = 1;
                    if (temp) {
                        newAccessNode->fileName = temp;
                    } else {
                        goto cleanup;
                    }
                } else if (!strcmp(cur_node->name, userTagName)) {
                    temp = parseUser(cur_node);
                    if (temp) {
                        newAccessNode->users[userIndex++] = temp;
                        newAccessNode->noOfUsers++;
                    } else {
                        goto cleanup;
                    }
                } else if (!strcmp(cur_node->name, groupTagName)) {
                    temp = parseGroup(cur_node);
                    if (temp) {
                        newAccessNode->groups[groupIndex++] = temp;
                        newAccessNode->noOfGroups++;
                    } else {
                        goto cleanup;
                    }
                } else if (!strcmp(cur_node->name, accessTagName) && !(accessParsed)) {
                    tempaccessMode = parseAccess(cur_node);
                    accessParsed = 1;
                    if (tempaccessMode < 0) {
                        goto cleanup;
                    } else {
                        newAccessNode->mode = (ulong) tempaccessMode;
                    }
                } else {
                    fprintf(stderr, "\nInvalid Element:%s\n", cur_node->name);
                    goto cleanup;
                }

            }
        }
    } else {
        fprintf(stderr, "Expected element : %s, as root node but found:%s", allowTagName, cur_node->name);
    }
ret:
    return newAccessNode;
cleanup:
    freePolicyElement(newAccessNode);
    newAccessNode = null;
    goto ret;

}

static aclList parsePermissions(xmlNode *node, aclList policyList) {
    xmlNode *cur_node = node;
    policyPtr accessNode = null;
    if (cur_node && cur_node->type == XML_ELEMENT_NODE && !strcmp(cur_node->name, permissionsTagName)) {
        for (cur_node = node->children; cur_node; cur_node = cur_node->next) {
            if (cur_node->type == XML_ELEMENT_NODE) {
                if (!strcmp(cur_node->name, allowTagName)) {
                    accessNode = parsePermission(cur_node, 1);
                    if (accessNode) {
                        insertAtBack(policyList, accessNode);
                    } else {
                        return null;
                    }
                } else if (!strcmp(cur_node->name, denyTagName)) {
                    accessNode = parsePermission(cur_node, 0);
                    if (accessNode) {
                        insertAtStart(policyList, accessNode);
                    } else {
                        return null;
                    }
                } else {
                    fprintf(stderr, "\nInvalid Element:%s\n", cur_node->name);
                }

            }
        }
    } else {
        fprintf(stderr, "Expected element : %s, as root node but found:%s", permissionsTagName, cur_node->name);
    }
    return policyList;
}

static aclList
parsePolicyXml(xmlNode * a_node) {
    xmlNode *cur_node = a_node;
    aclList policyList = null;
    if (cur_node && cur_node->type == XML_ELEMENT_NODE && !strcmp(cur_node->name, policyTagName)) {
        policyList = getNewPolicyList();
        for (cur_node = a_node->children; cur_node; cur_node = cur_node->next) {
            if (cur_node->type == XML_ELEMENT_NODE) {
                if (!strcmp(cur_node->name, permissionsTagName)) {
                    if (!parsePermissions(cur_node, policyList)) {
                        freePolicyList(policyList);
                        policyList = null;
                        break;
                    }
                } else {
                    fprintf(stderr, "\nInvalid Element:%s\n", cur_node->name);
                    freePolicyList(policyList);
                    policyList = null;
                    break;
                }

            }
        }
    } else {
        fprintf(stderr, "Expected element : %s, as root node but found:%s", policyTagName, cur_node->name);
    }
    return policyList;
}

aclList getAccessList(const char *policyfile) {
    aclList policyList = null;
    xmlDoc *doc = null;
    doc = xmlReadFile(policyfile, null, 0);

    if (doc == null) {
        fprintf(stderr, "error: could not parse policy file %s\n", policyfile);
    } else {
        xmlNode *root_element = null;
        root_element = xmlDocGetRootElement(doc);
        policyList = parsePolicyXml(root_element);
        if (!policyList) {
            fprintf(stderr, "Policy file incorrectly formed: %s\n", policyfile);
        }
        xmlFreeDoc(doc);
    }
    return policyList;
}


