using Firewall.Core.Models;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Net;
using System.Net.NetworkInformation;
using System.Runtime.InteropServices;

namespace Firewall.Core.Services
{
    public class ActiveConnectionsService
    {
        // Импорт системной библиотеки для получения таблиц соединений и имён процессов
        [DllImport("iphlpapi.dll", SetLastError = true)]
        private static extern uint GetExtendedTcpTable(IntPtr pTcpTable, ref int dwOutBufLen, bool bOrder, uint ulAf, TCP_TABLE_CLASS TableClass, uint Reserved = 0);
        [DllImport("iphlpapi.dll", SetLastError = true)]
        private static extern uint GetExtendedUdpTable(IntPtr pUdpTable, ref int dwOutBufLen, bool bOrder, uint ulAf, UDP_TABLE_CLASS TableClass, uint Reserved = 0);

        private const uint AF_INET = 2;
        private const uint AF_INET6 = 23;

        private enum TCP_TABLE_CLASS
        {
            TCP_TABLE_BASIC_LISTENER,
            TCP_TABLE_BASIC_CONNECTIONS,
            TCP_TABLE_BASIC_ALL,
            TCP_TABLE_OWNER_PID_LISTENER,
            TCP_TABLE_OWNER_PID_CONNECTIONS,
            TCP_TABLE_OWNER_PID_ALL,
            TCP_TABLE_OWNER_MODULE_LISTENER,
            TCP_TABLE_OWNER_MODULE_CONNECTIONS,
            TCP_TABLE_OWNER_MODULE_ALL
        }

        private enum UDP_TABLE_CLASS
        {
            UDP_TABLE_BASIC,
            UDP_TABLE_OWNER_PID,
            UDP_TABLE_OWNER_MODULE
        }

        // Структуры для получения данных
        [StructLayout(LayoutKind.Sequential)]
        private struct MIB_TCPROW_OWNER_PID
        {
            public uint state;
            public uint localAddr;
            public uint localPort;
            public uint remoteAddr;
            public uint remotePort;
            public int owningPid;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct MIB_TCPTABLE_OWNER_PID
        {
            public uint dwNumEntries;
            private MIB_TCPROW_OWNER_PID table;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct MIB_UDPROW_OWNER_PID
        {
            public uint localAddr;
            public uint localPort;
            public int owningPid;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct MIB_UDPTABLE_OWNER_PID
        {
            public uint dwNumEntries;
            private MIB_UDPROW_OWNER_PID table;
        }

        public List<ActiveConnection> GetConnections()
        {
            var connections = new List<ActiveConnection>();
            try
            {
                // Получаем список процессов, чтобы потом подставить имена по PID
                var processes = Process.GetProcesses().ToDictionary(p => p.Id);

                // Получаем TCP и UDP соединения с информацией о процессах
                var tcpConnections = GetTcpConnections(processes);
                var udpConnections = GetUdpConnections(processes);

                connections.AddRange(tcpConnections);
                connections.AddRange(udpConnections);
            }
            catch (Exception ex)
            {
                Debug.WriteLine($"Ошибка при получении подключений: {ex.Message}");
            }
            return connections;
        }

        private List<ActiveConnection> GetTcpConnections(Dictionary<int, Process> processes)
        {
            var connections = new List<ActiveConnection>();
            int bufferSize = 0;
            // Определяем размер буфера
            GetExtendedTcpTable(IntPtr.Zero, ref bufferSize, true, AF_INET, TCP_TABLE_CLASS.TCP_TABLE_OWNER_PID_ALL);
            IntPtr tcpTablePtr = Marshal.AllocHGlobal(bufferSize);
            try
            {
                uint result = GetExtendedTcpTable(tcpTablePtr, ref bufferSize, true, AF_INET, TCP_TABLE_CLASS.TCP_TABLE_OWNER_PID_ALL);
                if (result == 0)
                {
                    // Получаем количество записей
                    var table = (MIB_TCPTABLE_OWNER_PID)Marshal.PtrToStructure(tcpTablePtr, typeof(MIB_TCPTABLE_OWNER_PID));
                    IntPtr rowPtr = (IntPtr)((long)tcpTablePtr + Marshal.SizeOf(table.dwNumEntries));
                    for (int i = 0; i < table.dwNumEntries; i++)
                    {
                        var row = (MIB_TCPROW_OWNER_PID)Marshal.PtrToStructure(rowPtr, typeof(MIB_TCPROW_OWNER_PID));
                        connections.Add(new ActiveConnection
                        {
                            Protocol = "TCP",
                            LocalAddress = $"{new IPAddress(row.localAddr)}:{IPAddress.NetworkToHostOrder((short)row.localPort)}",
                            RemoteAddress = $"{new IPAddress(row.remoteAddr)}:{IPAddress.NetworkToHostOrder((short)row.remotePort)}",
                            State = GetTcpState(row.state),
                            PID = row.owningPid,
                            ProcessName = processes.ContainsKey(row.owningPid) ? processes[row.owningPid].ProcessName : "Idle"
                        });
                        rowPtr = (IntPtr)((long)rowPtr + Marshal.SizeOf(typeof(MIB_TCPROW_OWNER_PID)));
                    }
                }
            }
            finally
            {
                Marshal.FreeHGlobal(tcpTablePtr);
            }
            return connections;
        }

        private List<ActiveConnection> GetUdpConnections(Dictionary<int, Process> processes)
        {
            var connections = new List<ActiveConnection>();
            int bufferSize = 0;
            GetExtendedUdpTable(IntPtr.Zero, ref bufferSize, true, AF_INET, UDP_TABLE_CLASS.UDP_TABLE_OWNER_PID);
            IntPtr udpTablePtr = Marshal.AllocHGlobal(bufferSize);
            try
            {
                uint result = GetExtendedUdpTable(udpTablePtr, ref bufferSize, true, AF_INET, UDP_TABLE_CLASS.UDP_TABLE_OWNER_PID);
                if (result == 0)
                {
                    var table = (MIB_UDPTABLE_OWNER_PID)Marshal.PtrToStructure(udpTablePtr, typeof(MIB_UDPTABLE_OWNER_PID));
                    IntPtr rowPtr = (IntPtr)((long)udpTablePtr + Marshal.SizeOf(table.dwNumEntries));
                    for (int i = 0; i < table.dwNumEntries; i++)
                    {
                        var row = (MIB_UDPROW_OWNER_PID)Marshal.PtrToStructure(rowPtr, typeof(MIB_UDPROW_OWNER_PID));
                        connections.Add(new ActiveConnection
                        {
                            Protocol = "UDP",
                            LocalAddress = $"{new IPAddress(row.localAddr)}:{IPAddress.NetworkToHostOrder((short)row.localPort)}",
                            RemoteAddress = "0.0.0.0:0",
                            State = "-",
                            PID = row.owningPid,
                            ProcessName = processes.ContainsKey(row.owningPid) ? processes[row.owningPid].ProcessName : "Idle"
                        });
                        rowPtr = (IntPtr)((long)rowPtr + Marshal.SizeOf(typeof(MIB_UDPROW_OWNER_PID)));
                    }
                }
            }
            finally
            {
                Marshal.FreeHGlobal(udpTablePtr);
            }
            return connections;
        }

        private string GetTcpState(uint state)
        {
            switch (state)
            {
                case 1: return "CLOSED";
                case 2: return "LISTENING";
                case 3: return "SYN_SENT";
                case 4: return "SYN_RECEIVED";
                case 5: return "ESTABLISHED";
                case 6: return "FIN_WAIT1";
                case 7: return "FIN_WAIT2";
                case 8: return "CLOSE_WAIT";
                case 9: return "CLOSING";
                case 10: return "LAST_ACK";
                case 11: return "TIME_WAIT";
                case 12: return "DELETE_TCB";
                default: return "UNKNOWN";
            }
        }
    }
}