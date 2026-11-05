import QtQuick
import Quickshell
import Quickshell.Io
import qs.Ui

BarWidget {
  id: root
  moduleName: "namil27.wireguard"

  readonly property string command: "@COMMAND@"
  property string statusLabel: "VPN: проверка…"
  property string statusDetail: ""
  property string statusClass: "inactive"

  implicitWidth: button.implicitWidth
  implicitHeight: button.implicitHeight

  Process {
    id: statusStream
    command: [root.command, "stream"]
    running: true
    stdout: SplitParser {
      onRead: function(line) {
        try {
          var result = JSON.parse(line)
          root.statusLabel = String(result.text || "VPN")
          root.statusDetail = String(result.tooltip || "")
          root.statusClass = String(result.class || "inactive")
        } catch (error) {
          root.statusLabel = "VPN: ошибка"
          root.statusDetail = "Не удалось прочитать состояние WireGuard"
          root.statusClass = "error"
        }
      }
    }
    onExited: {
      root.statusLabel = "VPN: ошибка"
      root.statusDetail = "Монитор состояния остановился"
      root.statusClass = "error"
      restartTimer.restart()
    }
  }

  Timer {
    id: restartTimer
    interval: 5000
    onTriggered: statusStream.running = true
  }

  WidgetButton {
    id: button
    anchors.fill: parent
    bar: root.bar
    text: root.statusLabel
    foreground: root.bar
      ? (root.statusClass === "error" ? root.bar.urgent : root.bar.barForeground)
      : "white"
    tooltipText: root.statusDetail

    onPressed: function(button) {
      if (button === Qt.RightButton)
        Quickshell.execDetached([root.command, "toggle"])
      else
        Quickshell.execDetached([root.command, "menu"])
    }
  }
}
