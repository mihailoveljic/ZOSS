using Newtonsoft.Json;

namespace AccomodationService
{
	public class AccomodationService : IAccomodationService
	{
		public void ReceiveInvoice(string json)
		{
			var invoice = JsonConvert.DeserializeObject(json, new JsonSerializerSettings
			{
				TypeNameHandling = TypeNameHandling.All,
			});
		}
	}
}