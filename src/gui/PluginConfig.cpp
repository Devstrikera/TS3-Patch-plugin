#include <QtWidgets/QMainWindow>
#include <memory>
#include <include/gui/PluginConfig.h>
#include <QtWidgets/QMessageBox>
#include <QtWidgets/QDialogButtonBox>
#include <QtWidgets/QCheckBox>
#include <include/config.h>
#include <include/core.h>
#include "include/gui/PluginConfig.h"
#include "ui_pluginconfig.h"

using namespace std;
using namespace gui;

unique_ptr<PluginConfig> ui_config;
void gui::initialize(void* qParentWidget) {
	if(ui_config) ui_config->show();
	else {
		ui_config.reset(new PluginConfig((QWidget*) qParentWidget));
		if(plugin::configuration) {
			ui_config->options()->license_enabled = plugin::configuration->license.enabled;
			ui_config->options()->blacklist_disabled = plugin::configuration->blacklist.enabled;

			ui_config->options()->Updater.enabled = plugin::configuration->update.enabled;
			ui_config->options()->Updater.popup_notify = plugin::configuration->update.notify_popup;
			ui_config->updateOptions();
		}
		ui_config->show();
	}
}

void gui::finalize() {
	if(ui_config)
		ui_config->close();
	ui_config.release(); //Object will be destroyed automatically by QT
}

PluginConfig::PluginConfig(QWidget *owner) : QDialog(owner) {
	ui.setupUi(this);

	this->updateOptions();
	QObject::connect(this->ui.flag_blacklist, &QCheckBox::stateChanged, this, [&](int) { this->options()->blacklist_disabled = this->ui.flag_blacklist->isChecked(); this->options()->changed = true; });
	QObject::connect(this->ui.flag_updater_enabled, &QCheckBox::stateChanged, this, [&](int) { this->options()->Updater.enabled = this->ui.flag_updater_enabled->isChecked(); this->options()->changed = true; });
	QObject::connect(this->ui.flag_update_popup_notify, &QCheckBox::stateChanged, this, [&](int) { this->options()->Updater.popup_notify = this->ui.flag_update_popup_notify->isChecked(); this->options()->changed = true; });
	QObject::connect(this->ui.flag_teaspeak, &QCheckBox::stateChanged, this, [&](int) { this->options()->license_enabled = this->ui.flag_teaspeak->isChecked(); this->options()->changed = true; });

	QObject::connect(this->ui.buttons, &QDialogButtonBox::clicked, this, [&](QAbstractButton* _button) {
		auto button = reinterpret_cast<QPushButton*>(_button);
		if(button == this->ui.buttons->button(QDialogButtonBox::Save))
			this->btn_save_clicked();
		else if(button == this->ui.buttons->button(QDialogButtonBox::Close))
			this->btn_close_clicked();
	});

	this->setAttribute(Qt::WA_DeleteOnClose, true);
}

PluginConfig::~PluginConfig() {
	if(ui_config.get() == this)
		ui_config.release();
}

void PluginConfig::updateOptions() {
	if(!this->_options)
		this->_options = make_shared<PluginConfigOptions>();
	this->ui.flag_blacklist->setChecked(this->options()->blacklist_disabled);
	this->ui.flag_teaspeak->setChecked(this->options()->license_enabled);
	this->ui.flag_update_popup_notify->setChecked(this->options()->Updater.popup_notify);
	this->ui.flag_updater_enabled->setChecked(this->options()->Updater.enabled);
}

void PluginConfig::btn_close_clicked() {
	if(this->options()->changed)
		if(QMessageBox::warning(this, "Are you sure?", "Do you really want to quit?\nYou did not save your changes!", QMessageBox::Save | QMessageBox::Close) == QMessageBox::Save)
			this->btn_save_clicked();
	this->close();
}

void PluginConfig::btn_save_clicked() {
	this->options()->changed = false;

	if(plugin::configuration) {
		plugin::configuration->license.enabled = ui_config->options()->license_enabled;
		plugin::configuration->blacklist.enabled = ui_config->options()->blacklist_disabled;

		plugin::configuration->update.enabled = ui_config->options()->Updater.enabled;
		plugin::configuration->update.notify_popup = ui_config->options()->Updater.popup_notify;
	}

	string error;
	if(!plugin::config::save(error)) QMessageBox::critical(this, QString::fromStdString(plugin::name()), QString::fromStdString("Could not save config!\nError: " + error));
	else QMessageBox::information(this, QString::fromStdString(plugin::name()), "Successfully saved!");
}