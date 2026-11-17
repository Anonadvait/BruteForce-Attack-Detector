#ifndef QUEUE_H
#define QUEUE_H

#include "database.h"
#include <stdbool.h>

#define MAX_QUEUE 100

/*
 * Queue (FIFO - First In, First Out)
 * Stores incoming login attempts waiting to be processed.
 * Uses a circular array implementation to prevent element drifting.
 */
typedef struct {
    LoginAttempt items[MAX_QUEUE];
    int front;
    int rear;
    int count;
} Queue;

void initQueue(Queue *q);
bool isQueueEmpty(const Queue *q);
bool isQueueFull(const Queue *q);
bool enqueue(Queue *q, LoginAttempt item);
bool dequeue(Queue *q, LoginAttempt *item);
void displayQueue(const Queue *q);
int  getQueueSize(const Queue *q);
bool peekQueue(const Queue *q, LoginAttempt *item);

#endif /* QUEUE_H */
