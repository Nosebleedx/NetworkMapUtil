using System;
using SaltwaterTaffy;
using SaltwaterTaffy.Container;

class Program
{
	static void Main(string[] args)
	{
		string NmapPath = "C:\\Program Files (x86)\\Nmap\\nmap.exe";
        Console.WriteLine(NmapPath);

        try
		{
			var Nmap = new NmapContext();
			Nmap.Path = NmapPath;
			var targetHost = "192.168.0.0/24";
			var targetHost1 = "10.0.0.1/24 - 10";
			var targetSite = "scanme.nmap.org";
			var target = new Target(targetSite);
			var scanner = new Scanner(target);
			
			// Выполняем обнаружение хостов
			var hostDiscoveryResult = scanner.HostDiscovery();
			Console.WriteLine("----------------------------");
			Console.WriteLine("----------------------------");
			Console.WriteLine("----------------------------");
			Console.WriteLine("=== Host Discovery Results ===");
			Console.WriteLine();
			Console.WriteLine();
			foreach (var host in hostDiscoveryResult)
			{
				var hostNames = host.Hostnames;
				if(hostNames != null)
				{
					foreach (var hostName in hostNames)
					{
						Console.WriteLine(hostName);
					}
				}
				Console.WriteLine("----------------------------");
				Console.WriteLine("host Address: " + host.Address.ToString());
				Console.WriteLine("----------------------------");

				var hostPorts = host.Ports;
				foreach (var port in hostPorts)
				{
                    Console.WriteLine($"port number: {port.PortNumber}");
                    Console.WriteLine($"port service: {port.Service.Name} {port.Service.Version} {port.Service.Product}");
                    Console.WriteLine($"port protocol: {port.Protocol}");
                    Console.WriteLine($"port state: {port.State}");
                    Console.WriteLine($"port Filtered: {port.Filtered}");
					Console.WriteLine("----------------------------");

				}
				Console.WriteLine("----------------------------");
				var hostOSMatches = host.OsMatches;
				foreach (var hostOSMatch in hostOSMatches) 
				{
					Console.WriteLine("host OS name: "+hostOSMatch.Name);
                    Console.WriteLine($"host OS generation: {hostOSMatch.Generation}");
                    Console.WriteLine($"host OS Family: {hostOSMatch.Family}");
                    Console.WriteLine($"host OS Certainty: {hostOSMatch.Certainty}");
					Console.WriteLine("----------------------------");
				}

				Console.WriteLine("----------------------------");
				var hiddenPorts = host.ExtraPorts;
				foreach(var hiddenPort in hiddenPorts)
				{
					Console.WriteLine($"ExtraPort state: {hiddenPort.State}");
					Console.WriteLine($"ExtraPort count: {hiddenPort.Count}");
					Console.WriteLine("----------------------------");
				}
				Console.WriteLine("----------------------------");


			}

			Console.WriteLine();
			
			/*// Выполняем сканирование портов (TCP SYN)
			var portScanResult = scanner.PortScan(ScanType.Syn);
			Console.WriteLine("----------------------------");
			Console.WriteLine("----------------------------");
			Console.WriteLine("----------------------------");
			Console.WriteLine("=== Port Scan Results ===");*/
			
		}
		catch (Exception ex)
		{
			Console.WriteLine($"An error occurred: {ex.Message}");
		}
	}
}
