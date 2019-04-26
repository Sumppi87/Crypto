#ifdef USE_THREADS

#include "TaskManager.h"
#include <thread>
#include <list>
#include <algorithm>

TaskManager TaskManager::TASK_MANAGER;

void TaskManager::AddTask(Task* pTask)
{
	std::unique_lock lock(TASK_MANAGER.m_tasksLock);
	TASK_MANAGER.m_tasks.push_back(pTask);
	TASK_MANAGER.m_taskCondition.notify_one();
}

void TaskManager::ExecuteFunction(const std::function<void()>& func, const uint8_t threadCount)
{
	std::vector<Task*> tasks;
	for (uint32_t i = 0; i < threadCount; ++i)
	{
		Task* pTask = new Task(func);
		tasks.push_back(pTask);
		TaskManager::AddTask(pTask);
	}

	std::for_each(tasks.begin(), tasks.end(), [](Task* pTask)
	{
		pTask->WaitForFinished();
		delete pTask;
	});
}

unsigned int TaskManager::OptimalThreadCount()
{
	return std::thread::hardware_concurrency();
}

TaskManager::TaskManager()
	: m_running(true)
{
	std::function<void()> f = std::bind(&TaskManager::TaskFunction, this);
	for (unsigned int i = 0; i < std::thread::hardware_concurrency() * 2; ++i)
	{
		m_threadPool.push_back(new std::thread(f));
	}
}

TaskManager::~TaskManager()
{
	{
		std::unique_lock lock(m_tasksLock);
		m_running = false;
		m_taskCondition.notify_all();
	}

	std::for_each(m_threadPool.begin(), m_threadPool.end(), [](std::thread* pThread)
	{
		pThread->join();
		delete pThread;
	});
	m_threadPool.clear();
}

Task* TaskManager::GetTask()
{
	std::unique_lock lock(m_tasksLock);

	while (m_running && m_tasks.size() == 0)
	{
		m_taskCondition.wait(lock);
	}
	if (!m_running)
		return nullptr;

	Task* pTask = m_tasks.front();
	m_tasks.pop_front();
	return pTask;
}

void TaskManager::TaskFunction()
{
	while (m_running)
	{
		if (Task* pTask = GetTask())
		{
			pTask->Execute();
		}
		else if (!m_running)
		{
			break;
		}
		else
		{
			throw std::exception("Invalid Task pointer");
		}
	}
}
#endif // USE_THREADS