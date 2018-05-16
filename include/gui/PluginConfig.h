#pragma once

#include <memory>
#include <QtWidgets/QWidget>
#include "ui_pluginconfig.h"

namespace gui {
	struct PluginConfigOptions {
		bool blacklist_disabled = true;
		bool license_enabled = true;

		struct {
			bool enabled = true;
			bool popup_notify = true;
		} Updater;

		//Internal use
		bool changed = false;
	};

	class PluginConfig : public QDialog {
		Q_OBJECT
		public:
			PluginConfig(QWidget *owner);
			~PluginConfig();

			std::shared_ptr<PluginConfigOptions> options() { return this->_options; }
			void updateOptions();
		private:
			void btn_close_clicked();
			void btn_save_clicked();

			Ui::PluginConfig ui;
			std::shared_ptr<PluginConfigOptions> _options;
	};

	extern void initialize(void *qParentWidget);
}