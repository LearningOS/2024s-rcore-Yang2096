//!Implementation of [`TaskManager`]
use super::TaskControlBlock;
use crate::sync::UPSafeCell;
use alloc::collections::BinaryHeap;
use alloc::sync::Arc;
use lazy_static::*;
///A array of `TaskControlBlock` that is thread-safe
pub struct TaskManager {
    ready_tree: alloc::collections::BinaryHeap<CmpNode>
}

static BIG_STRIDE : usize = 1000;

struct CmpNode {
    tcb: Arc<TaskControlBlock>,
    pass: usize,
}

impl Eq for CmpNode {
}

impl PartialEq for CmpNode {
    fn eq(&self, other: &Self) -> bool {
         self.pass == other.pass
    }
}

impl PartialOrd for CmpNode {
    fn partial_cmp(&self, other: &Self) -> Option<core::cmp::Ordering> {
        self.pass.partial_cmp(&other.pass).map(|ord| ord.reverse())
    }
}

impl Ord for CmpNode {
    fn cmp(&self, other: &Self) -> core::cmp::Ordering {
        self.pass.cmp(&other.pass).reverse()
    }
}


/// A simple FIFO scheduler.
impl TaskManager {
    ///Creat an empty TaskManager
    pub fn new() -> Self {
        Self {
            ready_tree: BinaryHeap::new(),
        }
    }
    /// Add process back to ready queue
    pub fn add(&mut self, task: Arc<TaskControlBlock>) {
        // self.ready_queue.push_back(task);
        let mut inner = task.inner_exclusive_access();
        inner.pass += BIG_STRIDE / inner.priority;
        let pass = inner.pass;
        drop(inner);
        self.ready_tree.push(CmpNode { tcb: task, pass });
    }
    /// Take a process out of the ready queue
    pub fn fetch(&mut self) -> Option<Arc<TaskControlBlock>> {
        self.ready_tree.pop().map(|node| node.tcb)
    }
}

lazy_static! {
    /// TASK_MANAGER instance through lazy_static!
    pub static ref TASK_MANAGER: UPSafeCell<TaskManager> =
        unsafe { UPSafeCell::new(TaskManager::new()) };
}

/// Add process to ready queue
pub fn add_task(task: Arc<TaskControlBlock>) {
    //trace!("kernel: TaskManager::add_task");
    TASK_MANAGER.exclusive_access().add(task);
}

/// Take a process out of the ready queue
pub fn fetch_task() -> Option<Arc<TaskControlBlock>> {
    //trace!("kernel: TaskManager::fetch_task");
    TASK_MANAGER.exclusive_access().fetch()
}
