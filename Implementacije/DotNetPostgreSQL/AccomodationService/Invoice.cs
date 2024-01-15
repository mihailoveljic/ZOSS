namespace AccomodationService
{
	public sealed class Invoice
	{
		public Invoice(string name, double price, int quantity)
		{
			Name = name;
			Price = price;
			Quantity = quantity;
		}

		public string Name { get; set; }
		public double Price { get; set; }
		public int Quantity { get; set; }
	}
}
