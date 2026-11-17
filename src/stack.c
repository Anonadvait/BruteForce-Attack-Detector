#include "stack.h"
#include <stdio.h>
#include <string.h>

void initStack(Stack *s) {
    if (!s) return;
    s->top = -1;
    memset(s->items, 0, sizeof(s->items));
}

bool isStackEmpty(const Stack *s) {
    if (!s) return true;
    return (s->top < 0);
}

bool isStackFull(const Stack *s) {
    if (!s) return false;
    return (s->top >= MAX_STACK - 1);
}

bool push(Stack *s, LoginAttempt item) {
    if (!s) return false;

    if (isStackFull(s)) {
        fprintf(stderr, "[STACK ERROR] Overflow! Stack is full (Max: %d).\n", MAX_STACK);
        return false;
    }

    s->top++;
    s->items[s->top] = item;
    return true;
}

bool pop(Stack *s, LoginAttempt *item) {
    if (!s) return false;

    if (isStackEmpty(s)) {
        fprintf(stderr, "[STACK ERROR] Underflow! Stack is empty.\n");
        return false;
    }

    if (item) {
        *item = s->items[s->top];
    }
    s->top--;
    return true;
}

bool peek(const Stack *s, LoginAttempt *item) {
    if (!s || isStackEmpty(s)) return false;

    if (item) {
        *item = s->items[s->top];
    }
    return true;
}

int getStackSize(const Stack *s) {
    if (!s) return 0;
    return s->top + 1;
}

void displayStack(const Stack *s) {
    if (!s) return;

    int count = s->top + 1;
    printf("\n=== RECENT ACTIVITY STACK (LIFO) [Count: %d / %d] ===\n", count, MAX_STACK);
    if (isStackEmpty(s)) {
        printf("  [Empty Stack - No recent activity]\n");
        printf("======================================================\n\n");
        return;
    }

    printf("  Index | Pos   | Status  | User            | IP Address       | Timestamp\n");
    printf("  ------+-------+---------+-----------------+------------------+--------------------\n");

    for (int i = s->top; i >= 0; --i) {
        const char *pos = (i == s->top) ? "TOP" : "   ";
        const char *st = (s->items[i].status == STATUS_SUCCESS) ? "SUCCESS" : "FAILED ";

        printf("  %-5d | %-5s | %-7s | %-15s | %-16s | %s\n",
               i,
               pos,
               st,
               s->items[i].username,
               s->items[i].ip_address,
               s->items[i].timestamp);
    }
    printf("======================================================\n\n");
}
