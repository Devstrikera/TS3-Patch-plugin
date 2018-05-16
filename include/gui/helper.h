#pragma once

#include <QTimer>
#include <QThread>
#include <QApplication>

template <typename Func>
inline void runOnThread(QThread *qThread, Func &&func)
{
	if(qThread == QThread::currentThread()){
		func();
		return;
	}

	QTimer *t = new QTimer();
	t->moveToThread(qThread);
	t->setSingleShot(true);
	QObject::connect(t, &QTimer::timeout, [=]()
	{
		func();
		t->deleteLater();
	});
	QMetaObject::invokeMethod(t, "start", Qt::QueuedConnection, Q_ARG(int, 0));
}