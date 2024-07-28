//! Implementation of [`TaskManager`]
//!
//! It is only used to manage processes and schedule process based on ready queue.
//! Other CPU process monitoring functions are in Processor.

use super::TaskControlBlock;
use crate::sync::UPSafeCell;
use alloc::collections::{BTreeMap, BinaryHeap};
use alloc::sync::Arc;
use lazy_static::*;

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
    /// PID2PCB instance (map of pid to pcb)
    pub static ref PID2TCB: UPSafeCell<BTreeMap<usize, Arc<TaskControlBlock>>> =
        unsafe { UPSafeCell::new(BTreeMap::new()) };
}

/// Add process to ready queue
pub fn add_task(task: Arc<TaskControlBlock>) {
	//trace!("kernel: TaskManager::add_task");
    PID2TCB
        .exclusive_access()
        .insert(task.getpid(), Arc::clone(&task));
    TASK_MANAGER.exclusive_access().add(task);
}

/// Take a process out of the ready queue
pub fn fetch_task() -> Option<Arc<TaskControlBlock>> {
	//trace!("kernel: TaskManager::fetch_task");
    TASK_MANAGER.exclusive_access().fetch()
}

/// Get process by pid
pub fn pid2task(pid: usize) -> Option<Arc<TaskControlBlock>> {
    let map = PID2TCB.exclusive_access();
    map.get(&pid).map(Arc::clone)
}

/// Remove item(pid, _some_pcb) from PDI2PCB map (called by exit_current_and_run_next)
pub fn remove_from_pid2task(pid: usize) {
    let mut map = PID2TCB.exclusive_access();
    if map.remove(&pid).is_none() {
        panic!("cannot find pid {} in pid2task!", pid);
    }
}
