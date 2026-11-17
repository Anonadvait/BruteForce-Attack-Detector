#ifndef STACK_H
#define STACK_H

#include "database.h"
#include <stdbool.h>

#define MAX_STACK 100

/*
 * Stack (LIFO - Last In, First Out)
 * Maintains a history of recently processed login attempts.
 * The top element is always the most recently processed attempt.
 */
typedef struct {
    LoginAttempt items[MAX_STACK];
    int top;
} Stack;

void initStack(Stack *s);
bool isStackEmpty(const Stack *s);
bool isStackFull(const Stack *s);
bool push(Stack *s, LoginAttempt item);
bool pop(Stack *s, LoginAttempt *item);
bool peek(const Stack *s, LoginAttempt *item);
void displayStack(const Stack *s);
int  getStackSize(const Stack *s);

#endif /* STACK_H */
