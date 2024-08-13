use alloc::vec;
use alloc::vec::Vec;

/// backer algorithm
pub struct BankerAlgo {
    availiable: Vec<u32>,
    allocation: Vec<Vec<u32>>,
    need: Vec<Vec<u32>>,
}

/// result of acquire check
#[derive(Debug, Clone, Copy)]
pub enum CheckResult {
    /// unsafe state
    Unsafe,
    /// safe state
    Safe,
}

#[deny(dead_code)]
impl BankerAlgo {
    /// create
    pub fn new() -> Self {
        Self {
            availiable: vec![],
            allocation: vec![],
            need: vec![],
        }
    }

    /// create a new thread
    pub fn new_thread(&mut self, thread_id: usize) {
        if self.allocation.len() <= thread_id {
            self.allocation.push(vec![0; self.availiable.len()]);
            self.need.push(vec![0; self.availiable.len()]);
        } else {
            self.allocation[thread_id] = vec![0; self.availiable.len()];
            self.need[thread_id] = vec![0; self.availiable.len()];
        }
    }

    /// create a new resource
    pub fn new_resource(&mut self, resource_id: usize, avail: u32) {
        if self.availiable.len() <= resource_id {
            self.availiable.push(avail);
            self.allocation
                .iter_mut()
                .for_each(|per_thread| per_thread.push(0));
            self.need
                .iter_mut()
                .for_each(|per_thread| per_thread.push(0));
        } else {
            self.availiable[resource_id] = avail;
            self.allocation
                .iter_mut()
                .for_each(|per_thread| per_thread[resource_id] = 0);
            self.need
                .iter_mut()
                .for_each(|per_thread| per_thread[resource_id] = 0);
        }
    }

    #[allow(dead_code)]
    fn print(&self) {
        print!("availiable: ");
        for avail in self.availiable.iter() {
            print!("{},", avail)
        }
        println!("\nneed:");
        for (i, need) in self.need.iter().enumerate() {
            print!("{}: ", i);
            for n in need.iter() {
                print!("{},", n);
            }
            println!("");
        }
        println!("alloc:");
        for (i, alloc) in self.allocation.iter().enumerate() {
            print!("{}: ", i);
            for n in alloc.iter() {
                print!("{},", n);
            }
            println!("");
        }
    }

    ///
    pub fn post_acquire(&mut self, resource_id: usize, thread_id: usize, num: u32) {
        self.availiable[resource_id] -= num;
        self.need[thread_id][resource_id] -= num;
        self.allocation[thread_id][resource_id] += num;
    }

    /// acquire check
    pub fn acquire_check(&mut self, resource_id: usize, thread_id: usize, num: u32) -> CheckResult {
        self.need[thread_id][resource_id] += num;
        if num <= self.availiable[resource_id] {
            return CheckResult::Safe;
        }

        let mut vis = vec![false; self.allocation.len()];
        let result = self.loop_check(&mut vis, resource_id);
        // if let CheckResult::Unsafe = result {
        //     self.print();
        // }
        result
    }

    // 循环等待检查，根据所需要资源，查找持有它的线程，再根据这些线程所需的资源，检查资源的依赖链路
    fn loop_check(&self, vis: &mut Vec<bool>, resource_id: usize) -> CheckResult {
        for (tid, al) in self.allocation.iter().enumerate() {
            // 当前线程对于此资源无占用
            if al[resource_id] == 0 {
                continue;
            }
            for (r_id, need) in self.need[tid].iter().enumerate() {
                // 当前线程正在等待某一资源
                if *need > self.availiable[r_id] {
                    if vis[tid] {
                        // 出现循环依赖
                        return CheckResult::Unsafe;
                    }
                    vis[tid] = true;
                    // 针对当前线程等待的资源，递归检查是否有其他线程占用了它
                    if let CheckResult::Unsafe = self.loop_check(vis, r_id) {
                        return CheckResult::Unsafe;
                    }
                    vis[tid] = false;
                }
            }
        }
        CheckResult::Safe
    }

    /// release a resource
    pub fn release(&mut self, resource_id: usize, thread_id: usize, num: u32) {
        self.availiable[resource_id] += num;
        // self.need[thread_id][resource_id] += num;
        self.allocation[thread_id][resource_id] -= num;
    }
}
