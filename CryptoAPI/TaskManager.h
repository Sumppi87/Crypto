#pragma once
#ifdef USE_THREADS

#include <functional>
#include <mutex>
#include <condition_variable>

class Task
{
	enum class State : size_t
	{
		NOT_STARTED,
		RUNNING,
		FINISHED
	};
public:
	Task(const std::function<void()>& func);

	void Execute();

	bool IsFinished() const;

	void WaitForFinished();

private:
	Task(const Task&) = delete;
	Task(Task&&) = delete;
	Task& operator=(Task&) = delete;
	Task& operator=(Task&&) = delete;

private:
	std::function<void()> m_func;
	std::mutex m_lock;
	std::condition_variable m_cond;
	State m_state;
};

class TaskManager
{
public:
	static uint32_t THREADS;
	static void AddTask(Task* pTask);
	static void ExecuteFunction(const std::function<void()>& func, const uint32_t threadCount = THREADS);
	static unsigned int OptimalThreadCount();

	~TaskManager();

private:
	TaskManager(const TaskManager&) = delete;
	TaskManager(TaskManager&&) = delete;
	TaskManager& operator=(TaskManager&) = delete;
	TaskManager& operator=(TaskManager&&) = delete;

	static TaskManager TASK_MANAGER;

	TaskManager();
	Task* GetTask();
	void TaskFunction();

	std::condition_variable m_taskCondition;
	std::mutex m_tasksLock;
	std::list<Task*> m_tasks;
	std::vector<std::thread*> m_threadPool;

	bool m_running;
};

#endif // USE_THREADS