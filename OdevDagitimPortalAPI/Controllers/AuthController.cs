using OdevDagitimPortalAPI.DTOs;
using OdevDagitimPortalAPI.Services;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using System.Security.Claims;

namespace OdevDagitimPortalAPI.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class AuthController : ControllerBase
    {
        private readonly AuthService _authService;

        public AuthController(AuthService authService)
        {
            _authService = authService;
        }

        // user giriş metodu
        [HttpPost("login")]
        public async Task<IActionResult> Login([FromBody] LoginDTO model)
        {
            var token = await _authService.LoginAsync(model);
            if (token == null)
                return Unauthorized(new { Message = "Invalid username or password" });

            return Ok(token);
        }

        // user kayıt metodu

        [HttpPost("register")]
        public async Task<IActionResult> Register([FromBody] RegisterDTO model)
        {
            var result = await _authService.RegisterAsync(model);
            if (!result.Succeeded)
                return BadRequest(new { Errors = result.Errors.Select(e => e.Description) });

            return Ok(new { Message = "User registered successfully" });
        }

        // admin rol ekleme metodu

        [Authorize(Roles = "Admin")]
        [HttpPost("add-to-role")]
        public async Task<IActionResult> AddToRole(string userId, string role)
        {
            var result = await _authService.AddToRoleAsync(userId, role);
            if (!result.Succeeded)
                return BadRequest(new { Errors = result.Errors.Select(e => e.Description) });

            return Ok(new { Message = "Role added successfully" });
        }

        // admin rol kaldırma metodu

        [Authorize(Roles = "Admin")]
        [HttpPost("remove-from-role")]
        public async Task<IActionResult> RemoveFromRole(string userId, string role)
        {
            var result = await _authService.RemoveFromRoleAsync(userId, role);
            if (!result.Succeeded)
                return BadRequest(new { Errors = result.Errors.Select(e => e.Description) });

            return Ok(new { Message = "Role removed successfully" });
        }
       
        // tüm kullanıcıları listeleme metodu

        [Authorize]
        [HttpGet("user")]
        public async Task<IActionResult> GetUserInfo()
        {
            var userId = User.FindFirst(ClaimTypes.NameIdentifier)?.Value;
            if (string.IsNullOrEmpty(userId))
                return Unauthorized();

            var user = await _authService.GetUserByIdAsync(userId);
            if (user == null)
                return NotFound();

            return Ok(user);
        }

        // admin tüm kullanıcıları listeleme metodu

        [HttpGet("all-users")]
        [Authorize(Roles = "Admin")] // Sadece admin erişsin istiyorsan
        public async Task<IActionResult> GetAllUsers()
        {
            var users = await _authService.GetAllUsersAsync();
            return Ok(users);
        }
    }
}