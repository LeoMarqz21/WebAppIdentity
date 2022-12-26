using AutoMapper;
using WebAppIdentity.Models;
using WebAppIdentity.Models.ViewModels;

namespace WebAppIdentity.Services
{
    public class AutoMapperProfile : Profile
    {
        public AutoMapperProfile()
        {
            //source, target
            CreateMap<RegisterViewModel, User>();
            CreateMap<LoginViewModel, User>();
        }
    }
}
