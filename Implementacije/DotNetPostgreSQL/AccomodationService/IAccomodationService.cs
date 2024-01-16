using System.ServiceModel;

namespace AccomodationService
{
	[ServiceContract]
	public interface IAccomodationService
	{
		[OperationContract]
		void ReceiveInvoice(string json);
	}
}
