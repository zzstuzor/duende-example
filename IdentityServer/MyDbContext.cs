using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore;

namespace IdentityServer;

public sealed class MyDbContext : IdentityDbContext<IdentityUser>
{
    public MyDbContext()
        : base()
    {
    }

    public MyDbContext(DbContextOptions options)
        : base(options)
    {
    }
}
