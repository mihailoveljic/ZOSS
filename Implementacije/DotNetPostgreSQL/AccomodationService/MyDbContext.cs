using System.Data.Entity;

namespace AccomodationService
{
	public sealed class MyDbContext : DbContext
	{
		public MyDbContext() : base("YourConnectionString")
		{
			// Database configuration, if needed
		}

		public DbSet<User> Users { get; set; }
	}
}
