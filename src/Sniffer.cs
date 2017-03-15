// Copyright (c) 2017 TrakHound Inc, All Rights Reserved.

// This file is subject to the terms and conditions defined in
// file 'LICENSE.txt', which is part of this source code package.

using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using System.Runtime.InteropServices;
using System.Threading;

namespace TrakHound.MTConnectSniffer
{
    /// <summary>
    /// MTConnect Sniffer used to find MTConnect Devices on a network
    /// </summary>
    public class Sniffer
    {
        public delegate void DeviceHandler(MTConnectDevice device);
        public delegate void RequestStatusHandler(long milliseconds);
        public delegate void PingSentHandler(IPAddress address);
        public delegate void PingReceivedHandler(IPAddress address, PingReply reply);
        public delegate void PortRequestHandler(IPAddress address, int port);
        public delegate void ProbeRequestHandler(IPAddress address, int port);

        /// <summary>
        /// The timeout used for requests
        /// </summary>
        public int Timeout { get; set; }

        /// <summary>
        /// The delay in milliseconds between ping requests
        /// </summary>
        public int SubsequentPingDelay { get; set; }

        /// <summary>
        /// The range of ports to scan for MTConnect Agents at
        /// </summary>
        public int[] PortRange { get; set; }

        /// <summary>
        /// The range of IP Addresses to scan for MTConnect Agents at
        /// </summary>
        public IPAddress[] AddressRange { get; set; }

        /// <summary>
        /// Event raised when an MTConnect Device has been found
        /// </summary>
        public event DeviceHandler DeviceFound;

        /// <summary>
        /// Event raised when all requests have completed whether successful or not
        /// </summary>
        public event RequestStatusHandler RequestsCompleted;

        public event PingSentHandler PingSent;
        public event PingReceivedHandler PingReceived;
        public event PortRequestHandler PortOpened;
        public event PortRequestHandler PortClosed;
        public event ProbeRequestHandler ProbeSent;
        public event ProbeRequestHandler ProbeSuccessful;
        public event ProbeRequestHandler ProbeError;

        private Stopwatch stopwatch;
        private ManualResetEvent stop;
        private object _lock = new object();
        private PingQueue pingQueue;

        private int sentProbeRequests = 0;
        private int receivedProbeRequests = 0;

        public Sniffer()
        {
            Timeout = 500;
            SubsequentPingDelay = 25;

            // Initialize Ranges
            InitializePortRange();
            AddressRange = GetDefaultAddresses();
        }

        private void InitializePortRange()
        {
            int start = 5000;
            var size = 20;
            var portRange = new int[size];
            for (var i = 0; i < size; i++) portRange[i] = start++;
            PortRange = portRange;
        }

        /// <summary>
        /// Start the Sniffer to find MTConnect Devices on the network
        /// </summary>
        public void Start()
        {
            stop = new ManualResetEvent(false);

            stopwatch = new Stopwatch();
            stopwatch.Start();

            pingQueue = new PingQueue();
            pingQueue.Add(AddressRange.ToList());
            pingQueue.Completed += Queue_Completed;
            pingQueue.PingSent += PingQueue_PingSent;
            pingQueue.PingReceived += Queue_PingReceived;
            pingQueue.Start();
        }

        private void PingQueue_PingSent(IPAddress address)
        {
            PingSent?.Invoke(address);
        }

        private void Queue_PingReceived(IPAddress address, PingReply reply)
        {
            PingReceived?.Invoke(address, reply);
        }

        private void Queue_Completed(List<IPAddress> successfulAddresses)
        {
            foreach (var address in successfulAddresses)
            {
                if (stop.WaitOne(0, true)) break;

                foreach (int port in PortRange)
                {
                    ThreadPool.QueueUserWorkItem(new WaitCallback((o) =>
                    {
                        if (TestPort(address, port))
                        {
                            SendProbe(address, port);
                        }
                    }));

                    if (stop.WaitOne(0, true)) break;
                }
            }
        }

        public void Stop()
        {
            if (stop != null) stop.Set();

            if (pingQueue != null) pingQueue.Stop();
        }

        private void CheckRequestsStatus()
        {
            if (receivedProbeRequests >= sentProbeRequests)
            {
                long m = 0;

                if (stopwatch != null)
                {
                    stopwatch.Stop();
                    m = stopwatch.ElapsedMilliseconds;
                }

                RequestsCompleted?.Invoke(m);
            }
        }

        /// <summary>
        /// Get an array of Host Addresses for each Network Interface
        /// </summary>
        private IPAddress[] GetHostAddresses()
        {
            var interfaces = NetworkInterface.GetAllNetworkInterfaces();
            if (interfaces != null)
            {
                var addresses = new List<IPAddress>();

                foreach (var ni in interfaces)
                {
                    if (ni.OperationalStatus == OperationalStatus.Up && (ni.NetworkInterfaceType == NetworkInterfaceType.Wireless80211 || ni.NetworkInterfaceType == NetworkInterfaceType.Ethernet))
                    {
                        foreach (var ip in ni.GetIPProperties().UnicastAddresses)
                        {
                            if (ip.Address.AddressFamily == AddressFamily.InterNetwork)
                            {
                                addresses.Add(ip.Address);
                            }
                        }
                    }
                }

                return addresses.ToArray();
            }

            return null;
        }

        private IPAddress[] GetDefaultAddresses()
        {
            var l = new List<IPAddress>();

            var hosts = GetHostAddresses();
            if (hosts != null)
            {
                foreach (var host in hosts)
                {
                    IPNetwork ip;
                    if (IPNetwork.TryParse(host.ToString(), out ip))
                    {
                        var addresses = IPNetwork.ListIPAddress(ip);
                        if (addresses != null)
                        {
                            foreach (var address in addresses) l.Add(address);
                        }
                    }
                }
            }

            return l.ToArray();
        }

        private bool TestPort(IPAddress address, int port)
        {
            try
            {
                using (var client = new TcpClient())
                {
                    var result = client.BeginConnect(address, port, null, null);
                    var success = result.AsyncWaitHandle.WaitOne(Timeout);
                    if (!success)
                    {
                        PortClosed?.Invoke(address, port);
                        return false;
                    }
                    else
                    {
                        PortOpened?.Invoke(address, port);
                    }

                    client.EndConnect(result);
                }
            }
            catch
            {
                return false;
            }
            return true;
        }
        

        #region "MTConnect Probe"

        private class ProbeSender
        {
            public ProbeSender(IPAddress address, int port)
            {
                Address = address;
                Port = port;
            }

            public IPAddress Address { get; set; }
            public int Port { get; set; }
        }


        private void SendProbe(IPAddress address, int port)
        {
            try
            {
                var uri = new UriBuilder("http", address.ToString(), port);

                var probe = new MTConnect.Clients.Probe(uri.ToString());
                probe.UserObject = new ProbeSender(address, port);
                probe.Successful += Probe_Successful;
                probe.Error += Probe_Error;
                probe.ConnectionError += Probe_ConnectionError;
                sentProbeRequests++;
                ProbeSent?.Invoke(address, port);
                probe.ExecuteAsync();
            }
            catch { }      
        }

        private void Probe_ConnectionError(Exception ex)
        {
            IncrementProbeRequests();
        }

        private void Probe_Error(MTConnect.MTConnectError.Document errorDocument)
        {
            IncrementProbeRequests();

            if (errorDocument != null)
            {
                var sender = errorDocument.UserObject as ProbeSender;
                if (sender != null)
                {
                    ProbeError?.Invoke(sender.Address, sender.Port);
                }
            }
        }

        private void Probe_Successful(MTConnect.MTConnectDevices.Document document)
        {
            IncrementProbeRequests();

            if (document != null && document.UserObject != null)
            {
                var sender = document.UserObject as ProbeSender;
                if (sender != null)
                {
                    // Get the MAC Address of the sender
                    var macAddress = GetMacAddress(sender.Address);

                    foreach (var device in document.Devices)
                    {
                        DeviceFound?.Invoke(new MTConnectDevice(sender.Address, sender.Port, macAddress, device.Name));
                    }

                    ProbeSuccessful?.Invoke(sender.Address, sender.Port);
                }
            }
        }

        private void IncrementProbeRequests()
        {
            lock (_lock)
            {
                receivedProbeRequests++;
                CheckRequestsStatus();
            }
        }

        #endregion

        #region "MAC Address"

        [DllImport("iphlpapi.dll", ExactSpelling = true)]
        static extern int SendARP(int DestIP, int SrcIP, byte[] pMacAddr, ref int PhyAddrLen);

        /// <summary>
        /// Gets the MAC address (<see cref="PhysicalAddress"/>) associated with the specified IP.
        /// </summary>
        /// <param name="ipAddress">The remote IP address.</param>
        /// <returns>The remote machine's MAC address.</returns>
        private static PhysicalAddress GetMacAddress(IPAddress ipAddress)
        {
            const int MacAddressLength = 6;
            int length = MacAddressLength;
            var macBytes = new byte[MacAddressLength];
            if (SendARP(BitConverter.ToInt32(ipAddress.GetAddressBytes(), 0), 0, macBytes, ref length) == 0)
            {
                return new PhysicalAddress(macBytes);
            }

            return null;
        }

        #endregion
    }
}
