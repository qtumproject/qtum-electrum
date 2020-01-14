from PyQt5.QtWidgets import QWidget, QApplication

from electrum.gui.qt.stylesheet_patcher import patch_qt_stylesheet
from electrum.gui.qt.util import  ColorScheme

def set_qtum_theme_if_needed(self):
    use_dark_theme = self.config.get('qt_gui_color_theme', 'default') == 'dark'
    # Add switcher for Qtum core style themes on electrum
    use_qtum_theme1 = self.config.get('qt_gui_color_theme', 'default') == 'qtum_dark'
    use_qtum_theme2 = self.config.get('qt_gui_color_theme', 'default') == 'qtum_almost_dark'
    use_qtum_theme3 = self.config.get('qt_gui_color_theme', 'default') == 'qtum_light'
    self.app = QApplication.instance()
    if use_dark_theme:
        try:
            import qdarkstyle
            self.app.setStyleSheet(qdarkstyle.load_stylesheet_pyqt5())
        except BaseException as e:
            use_dark_theme = False
            self.logger.warning(f'Error setting dark theme: {repr(e)}')
    elif use_qtum_theme1:
        try:
            self.app.setStyleSheet(open('electrum/gui/qt/styles/theme1/app.css').read())
        except BaseException as e:
            use_dark_theme = False
            self.logger.warning(f'Error setting Qtum theme: {repr(e)}')
    elif use_qtum_theme2:
        try:
            self.app.setStyleSheet(open('electrum/gui/qt/styles/theme2/app.css').read())
        except BaseException as e:
            use_dark_theme = False
            self.logger.warning(f'Error setting Qtum theme: {repr(e)}')
    elif use_qtum_theme3:
        try:
            self.app.setStyleSheet(open('electrum/gui/qt/styles/theme3/app.css').read())
        except BaseException as e:
            use_dark_theme = False
            self.logger.warning(f'Error setting Qtum theme: {repr(e)}')
    else:
        try:
            self.app.setStyleSheet('')
        except BaseException as e:
            use_dark_theme = False
            self.logger.warning(f'Error setting Light theme: {repr(e)}')
    # Apply any necessary stylesheet patches
    patch_qt_stylesheet(use_dark_theme=use_dark_theme)
    # Even if we ourselves don't set the dark theme,
    # the OS/window manager/etc might set *a dark theme*.
    # Hence, try to choose colors accordingly:
    ColorScheme.update_from_widget(QWidget(), force_dark=use_dark_theme)