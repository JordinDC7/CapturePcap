using System;
using System.IO;
using PacketDotNet;
using SharpPcap;
using SharpPcap.LibPcap;

namespace DB_Packets
{
    class Program
    {
        static CaptureFileWriterDevice writer;
        private static bool isWriterOpen;

        static void Main(string[] args)
        {
            try
            {
                // List all available devices
                ListDevices();

                // Specify the exact path to save the .pcap file
                string filename = @"C:\Users\jordi\Desktop\DO Packets\DB PACKETS\DB PACKETS\captured_packets.pcap";

                // Ensure the directory exists
                string? directoryPath = Path.GetDirectoryName(filename);
                if (directoryPath == null)
                {
                    Console.WriteLine($"Invalid directory path: {filename}");
                    return;
                }
                if (!Directory.Exists(directoryPath))
                {
                    Console.WriteLine($"Directory does not exist: {directoryPath}");
                    Directory.CreateDirectory(directoryPath);
                    Console.WriteLine($"Directory created: {directoryPath}");
                }

                // Specify the index of the Ethernet device (0-based index)
                int deviceIndex = 6; // Adjust this index based on your device list

                // Open the specified device and start capturing packets
                using var device = LibPcapLiveDeviceList.Instance[deviceIndex];
                device.Open();
                device.OnPacketArrival += Device_OnPacketArrival;

                // Create a writer to write packets to the specified file
                InitializeWriter(filename);

                if (writer == null)
                {
                    Console.WriteLine("Error: Writer could not be opened.");
                    return;
                }

                Console.WriteLine($"Using device: {device.Description}");
                Console.WriteLine("Packet capture started. Press Enter to stop...");
                device.StartCapture();

                Console.ReadLine();

                device.StopCapture();
                Console.WriteLine("Packet capture stopped.");

                device.Close();
                writer.Close();
                isWriterOpen = false;
                Console.WriteLine("Device and writer closed successfully.");
                Console.WriteLine($"Packets have been captured and saved to {filename}");
            }
            catch (Exception e)
            {
                Console.WriteLine("Error occurred: " + e.Message);
            }
        }

        static void ListDevices()
        {
            var devices = CaptureDeviceList.Instance;
            int index = 0;
            foreach (var dev in devices)
            {
                Console.WriteLine($"[{index}] {dev.Description}");
                index++;
            }
        }

        private static void InitializeWriter(string filePath)
        {
            writer = new CaptureFileWriterDevice(filePath);
            writer.Open();
            isWriterOpen = true;
        }

        private static void Device_OnPacketArrival(object sender, PacketCapture e)
        {
            try
            {
                var packet = Packet.ParsePacket(e.GetPacket().LinkLayerType, e.GetPacket().Data);
                var tcpPacket = packet.Extract<TcpPacket>();

                if (tcpPacket != null)
                {
                    var ipPacket = tcpPacket.ParentPacket;
                    if (ipPacket is IPv4Packet ipv4Packet && ipv4Packet.DestinationAddress.ToString() == "170.33.13.202")
                    {
                        Console.WriteLine($"Packet captured at {e.Header.Timeval.Date} destined for {ipv4Packet.DestinationAddress}: {packet}");

                      
                        if (isWriterOpen)
                        {
                            writer.Write(e.GetPacket());
                            Console.WriteLine("Packet written to file.");
                        }
                        else
                        {
                            Console.WriteLine("Writer is not open. Packet not written.");
                        }
                    }
                    else if (ipPacket is IPv6Packet ipv6Packet && ipv6Packet.DestinationAddress.ToString() == "170.33.13.202")
                    {
                        Console.WriteLine($"Packet captured at {e.Header.Timeval.Date} destined for {ipv6Packet.DestinationAddress}: {packet}");

                        if (isWriterOpen)
                        {
                            writer.Write(e.GetPacket());
                            Console.WriteLine("Packet written to file.");
                        }
                        else
                        {
                            Console.WriteLine("Writer is not open. Packet not written.");
                        }
                    }
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine("Error during packet arrival handling: " + ex.Message);
            }
        }
    }
}
