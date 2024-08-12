## 问答作业
1. 请结合用例理解 [trap.S](https://github.com/rcore-os/rCore-Tutorial-v3/blob/ch2/os/src/trap/trap.S) 中两个函数 `__alltraps` 和 `__restore` 的作用，并回答如下几个问题:
	1. L40：刚进入 `__restore` 时，`a0` 代表了什么值。请指出 `__restore` 的两种使用情景。
		- `a0` 代表了内核栈的 sp 指针
		- 第一种：处理完 trap 之后返回用户程序流
		- 第二种：调用 next_app 时从内核态切换为用户态
        
    2. L46-L51：这几行汇编代码特殊处理了哪些寄存器？这些寄存器的的值对于进入用户态有何意义？请分别解释。
		```
        ld t0, 32*8(sp)
        ld t1, 33*8(sp)
        ld t2, 2*8(sp)
        csrw sstatus, t0
        csrw sepc, t1
        csrw sscratch, t2
		```
		- sstatus：特权级
		- spec：将要被执行的下一条用户程序指令
		- sscratch：用户栈的 sp 指针（栈顶）
        
    3. L53-L59：为何跳过了 `x2` 和 `x4`？
        ```
        ld x1, 1*8(sp)
        ld x3, 3*8(sp)
        .set n, 5
        .rept 27
           LOAD_GP %n
           .set n, n+1
        .endr
		```
		- 目前 x2 是正在运行的内核栈的栈顶，后面需要和 sscratch 进行交换
		- x4 没有被用到
        
    4. L63：该指令之后，`sp` 和 `sscratch` 中的值分别有什么意义？
        `csrrw sp, sscratch, sp`
        - 执行之后，sp 指向用户 stack 的栈顶，sscratch 执行内核栈的栈顶
        
    5. `__restore`：中发生状态切换在哪一条指令？为何该指令执行之后会进入用户态？
		- sret 

    1. L13：该指令之后，`sp` 和 `sscratch` 中的值分别有什么意义？
        `csrrw sp, sscratch, sp`
        - sp 指向内核栈栈顶
        - sscratch 执行用户栈栈顶
        
    7. 从 U 态进入 S 态是哪一条指令发生的？
	    - `syscall()` 里的 `ecall`