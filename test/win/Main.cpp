#include <iostream>
#include <include/update/updater.h>
#include <thread>

#include <QMainWindow>
#include <QtWidgets/QMessageBox>
#include <QtWidgets/QApplication>
#include <include/gui/PluginConfig.h>

using namespace std;
using namespace std::chrono;
using namespace update;

int main(int argc, char** argv) {
	QApplication app(argc, argv);
    cout << "Hello world" << endl;

    /*
    update::remote_version([](Version version) {
        cout << "Remote version: " << endl;

        cout << "Major: " << version.major << endl;
        cout << "Minor: " << version.minor << endl;
        cout << "Patch: " << version.patch << endl;

        cout << "Aditional: " << version.additional << endl;
        cout << "Timestamp: " << duration_cast<seconds>(version.timestamp.time_since_epoch()).count() << endl;
    });
    this_thread::sleep_for(seconds(5));
     */

	gui::initialize(nullptr); //Test :D
    //QMessageBox::warning(nullptr, "Hello", "World");
    return app.exec();
}