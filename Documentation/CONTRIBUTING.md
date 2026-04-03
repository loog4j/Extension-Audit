# Contributing to Browser Extension Audit

Thank you for your interest in contributing to this project! This tool helps organizations detect malicious browser extensions across their Windows endpoints.

## How to Contribute

### Reporting Issues

If you find a bug or have a feature request:

1. **Check existing issues** to avoid duplicates
2. **Open a new issue** with:
   - Clear title describing the problem/feature
   - Steps to reproduce (for bugs)
   - Expected vs actual behavior
   - PowerShell version and Windows version
   - Error messages (if any)

### Contributing Code

1. **Fork the repository**
2. **Create a feature branch**
   ```bash
   git checkout -b feature/your-feature-name
   ```
3. **Make your changes**
   - Follow existing code style
   - Add comments for complex logic
   - Update documentation if needed
4. **Test your changes**
   - Test on Windows 10 and Windows 11
   - Test with Chrome, Edge, Firefox, and Brave
   - Verify Event Log output
5. **Commit with clear messages**
   ```bash
   git commit -m "Add support for Opera browser"
   ```
6. **Push and create Pull Request**
   ```bash
   git push origin feature/your-feature-name
   ```

### Code Style Guidelines

- Use full PowerShell cmdlet names (not aliases)
- Add comment-based help for new functions
- Include error handling with try/catch
- Use meaningful variable names
- Add inline comments for complex regex or logic

### Adding Browser Support

To add support for a new browser:

1. Identify the browser's extension directory structure
2. Determine the extension manifest format
3. Add browser to the `$Browsers` hashtable
4. Handle browser-specific quirks (if any)
5. Update documentation
6. Test thoroughly

### Updating Malicious Extension Lists

We maintain `malicious_extensions.txt` based on:
- [Palant's Malicious Extensions List](https://github.com/palant/malicious-extensions-list)
- [Bowes Chrome Malicious IDs](https://github.com/mallorybowes/chrome-mal-ids)
- Security researcher reports
- Internal threat intelligence

**To submit new malicious extension IDs:**
1. Provide the extension ID
2. Provide evidence (security report, analysis, etc.)
3. Include when it was discovered
4. Note the threat type (miner, stealer, adware, etc.)

### Documentation Improvements

Documentation is just as important as code! Feel free to:
- Fix typos or clarify confusing sections
- Add examples or use cases
- Improve deployment guides
- Translate documentation (if multilingual support needed)

## Testing

Before submitting a PR:

- [ ] Script runs without errors on Windows 10
- [ ] Script runs without errors on Windows 11
- [ ] Events appear in Event Viewer with correct format
- [ ] Chrome extensions detected correctly
- [ ] Edge extensions detected correctly
- [ ] Firefox extensions detected correctly (if applicable)
- [ ] Brave extensions detected correctly (if applicable)
- [ ] Documentation updated (if needed)
- [ ] No PowerShell aliases used (full cmdlet names only)

## Questions?

- Open a GitHub Discussion for questions
- Check existing issues and documentation first
- Be respectful and constructive

## Code of Conduct

- Be respectful and inclusive
- Focus on constructive feedback
- Help others learn and grow
- Security first - report vulnerabilities privately

Thank you for contributing! 🎉
