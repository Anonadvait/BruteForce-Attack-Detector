#include "queue.h"
#include <stdio.h>
#include <string.h>

void initQueue(Queue *q) {
    if (!q) return;
    q->front = 0;
    q->rear = -1;
    q->count = 0;
    memset(q->items, 0, sizeof(q->items));
}

bool isQueueEmpty(const Queue *q) {
    if (!q) return true;
    return (q->count == 0);
}

bool isQueueFull(const Queue *q) {
    if (!q) return false;
    return (q->count >= MAX_QUEUE);
}

bool enqueue(Queue *q, LoginAttempt item) {
    if (!q) return false;

    if (isQueueFull(q)) {
        fprintf(stderr, "[QUEUE ERROR] Overflow! Queue is full (Max: %d).\n", MAX_QUEUE);
        return false;
    }

    q->rear = (q->rear + 1) % MAX_QUEUE;
    q->items[q->rear] = item;
    q->count++;
    return true;
}

bool dequeue(Queue *q, LoginAttempt *item) {
    if (!q) return false;

    if (isQueueEmpty(q)) {
        fprintf(stderr, "[QUEUE ERROR] Underflow! Queue is empty.\n");
        return false;
    }

    if (item) {
        *item = q->items[q->front];
    }

    q->front = (q->front + 1) % MAX_QUEUE;
    q->count--;
    return true;
}

bool peekQueue(const Queue *q, LoginAttempt *item) {
    if (!q || isQueueEmpty(q)) return false;
    if (item) {
        *item = q->items[q->front];
    }
    return true;
}

int getQueueSize(const Queue *q) {
    if (!q) return 0;
    return q->count;
}

void displayQueue(const Queue *q) {
    if (!q) return;

    printf("\n=== PENDING QUEUE (FIFO) [Count: %d / %d] ===\n", q->count, MAX_QUEUE);
    if (isQueueEmpty(q)) {
        printf("  [Empty Queue - No pending login attempts]\n");
        printf("=============================================\n\n");
        return;
    }

    printf("  Index | Pos   | User            | IP Address       | Source\n");
    printf("  ------+-------+-----------------+------------------+----------\n");

    int idx = q->front;
    for (int i = 0; i < q->count; ++i) {
        const char *tag = "";
        if (i == 0 && i == q->count - 1) {
            tag = "FRONT&REAR";
        } else if (i == 0) {
            tag = "FRONT";
        } else if (i == q->count - 1) {
            tag = "REAR";
        }

        printf("  %-5d | %-5s | %-15s | %-16s | %s\n",
               idx,
               tag,
               q->items[idx].username,
               q->items[idx].ip_address,
               (q->items[idx].ip_source == SOURCE_AUTOMATIC) ? "Auto" : "Manual");

        idx = (idx + 1) % MAX_QUEUE;
    }
    printf("=============================================\n\n");
}
