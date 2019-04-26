#pragma once
#ifdef USE_THREADS

#include <functional>
#include <mutex>
#include <condition_variable>

class Task
{
	enum State
	{
		NOT_STARTED,
		RUNNING,
		FINISHED
	};
public:
	Task(const std::function<void()>& func)
		: m_func(func)
		, m_state(State::NOT_STARTED) {}

	void Execute()
	{
		std::unique_lock lock(m_lock);
		m_state = State::RUNNING;
		//lock.unlock();

		if (m_func)
			m_func();

		m_state = State::FINISHED;
		m_cond.notify_all();
	}

	bool IsFinished() const
	{
		return m_state == State::FINISHED;
	}

	bool HasStarted() const
	{
		return m_state == State::RUNNING || m_state == State::FINISHED;
	}

	void WaitForFinished()
	{
		std::unique_lock lock(m_lock);

		// condition_variable::wait can wakeup spuriously
		while (!IsFinished())
		{
			m_cond.wait(lock);
		}
	}

private:
	State m_state;

	std::function<void()> m_func;
	std::mutex m_lock;
	std::condition_variable m_cond;
};

class TaskManager
{
public:
	static void AddTask(Task* pTask);
	static void ExecuteFunction(const std::function<void()>& func, const uint8_t threadCount = OptimalThreadCount());
	static unsigned int OptimalThreadCount();

	~TaskManager();

private:
	static TaskManager TASK_MANAGER;

	TaskManager();
	Task* GetTask();
	void TaskFunction();

	bool m_running;

	std::condition_variable m_taskCondition;
	std::mutex m_tasksLock;
	std::list<Task*> m_tasks;

	std::vector<std::thread*> m_threadPool;
};

#endif // USE_THREADS