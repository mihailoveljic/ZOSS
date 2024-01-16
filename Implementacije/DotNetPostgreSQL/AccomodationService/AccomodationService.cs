using Newtonsoft.Json;

namespace AccomodationService
{
	public class AccomodationService : IAccomodationService
	{
		private readonly FtpServerClient _ftpServerClient;

		public AccomodationService()
		{
			_ftpServerClient = new FtpServerClient();
		}

		public void ReceiveInvoice(string json)
		{
			Invoice invoice = (Invoice)JsonConvert.DeserializeObject(json, new JsonSerializerSettings
			{
				TypeNameHandling = TypeNameHandling.All,
			});

			_ftpServerClient.UploadToFtp(invoice);
		}
	}
}