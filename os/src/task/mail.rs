use alloc::{sync::Arc, vec::Vec};

use crate::{mm::UserBuffer, sync::UPSafeCell};

use super::suspend_current_and_run_next;

const BUFFER_SIZE: usize = 16;
const VIRTUAL_BUFFER_SIZE: usize = 32;

struct RingBuffer {
    buffer: [Option<Vec<u8>>; BUFFER_SIZE],
    head: usize,
    tail: usize,
}

impl RingBuffer {
    fn current_size(&self) -> usize {
        if self.tail < self.head {
            self.tail + VIRTUAL_BUFFER_SIZE - self.head
        } else {
            self.tail - self.head
        }
    }
}

pub struct MailPost {
    inner: Arc<UPSafeCell<RingBuffer>>,
}

impl Default for MailPost {
    fn default() -> Self {
        Self {
            inner: Arc::new(unsafe {
                UPSafeCell::new(RingBuffer {
                    buffer: Default::default(),
                    head: 0,
                    tail: 0,
                })
            }),
        }
    }
}

impl Clone for MailPost {
    fn clone(&self) -> Self {
        Self { inner: self.inner.clone() }
    }
}

impl MailPost {
    pub fn push(&mut self, content: UserBuffer) -> isize {
        loop {
            let mut ring_buffer = self.inner.exclusive_access();
            if ring_buffer.current_size() == BUFFER_SIZE {
                // full
                if content.len() == 0 {
                    return -1;
                }
                drop(ring_buffer);
                suspend_current_and_run_next();
                continue;
            }
            let len = content.len().min(256);
            let mut data = Vec::with_capacity(len);
            let mut byte_iter = content.into_iter();
            for _ in 0..len {
                data.push(unsafe { *byte_iter.next().unwrap() });
            }

            let tail = ring_buffer.tail;
            ring_buffer.buffer[tail % BUFFER_SIZE] = Some(data);
            ring_buffer.tail = (tail + 1) % VIRTUAL_BUFFER_SIZE;
            return 0;
        }
    }

    pub fn pop(&mut self, content: UserBuffer) -> isize {
        loop {
            let mut ring_buffer = self.inner.exclusive_access();
            if ring_buffer.current_size() == 0 {
                // empty
                if content.len() == 0 {
                    return -1;
                }
                drop(ring_buffer);
                suspend_current_and_run_next();
                continue;
            }
            let head = ring_buffer.head;
            ring_buffer.head = (head + 1) % VIRTUAL_BUFFER_SIZE;
            let data = ring_buffer.buffer[head % BUFFER_SIZE].take();
            assert!(data.is_some());
            let data = data.unwrap();
            let mut buf_iter = content.into_iter();
            for d in data {
                if let Some(byte_ref) = buf_iter.next() {
                    unsafe {
                        *byte_ref = d;
                    }
                } else {
                    break;
                }
            }
            return 0;
        }
    }
}
