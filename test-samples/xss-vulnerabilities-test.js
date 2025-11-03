// Test file for XSS and DOM manipulation vulnerabilities
// This file contains intentional security vulnerabilities for testing purposes

// VULNERABLE: Direct innerHTML assignment with user input
function displayUserComment(comment) {
    document.getElementById('comment-section').innerHTML = comment;
}

// VULNERABLE: Creating HTML from user input
function createUserProfile(userData) {
    const profileHtml = `
        <div class="profile">
            <h2>${userData.name}</h2>
            <p>${userData.bio}</p>
        </div>
    `;
    document.querySelector('.profiles').innerHTML += profileHtml;
}

// VULNERABLE: document.write with user input
function welcomeMessage(username) {
    document.write('<h1>Welcome, ' + username + '</h1>');
}

// VULNERABLE: jQuery html() with user input
function updateNotification(message) {
    $('#notification').html(message);
}

// VULNERABLE: Creating elements with user-controlled attributes
function createLink(url, text) {
    const link = `<a href="${url}" onclick="trackClick()">${text}</a>`;
    document.getElementById('links').innerHTML = link;
}

// VULNERABLE: eval() with user input
function calculateExpression(expr) {
    const result = eval(expr);
    return result;
}

// VULNERABLE: setTimeout with string
function delayedAction(code) {
    setTimeout(code, 1000);
}

// VULNERABLE: Direct DOM manipulation
function addListItem(itemText) {
    const list = document.getElementById('myList');
    list.innerHTML = list.innerHTML + '<li>' + itemText + '</li>';
}

// SAFE: Example of sanitized approach (for comparison)
function safeDisplayComment(comment) {
    const textNode = document.createTextNode(comment);
    document.getElementById('safe-comments').appendChild(textNode);
}

// VULNERABLE: Template literal with user data in event handler
function addButton(buttonLabel, action) {
    const button = `<button onclick="${action}">${buttonLabel}</button>`;
    document.body.innerHTML += button;
}

module.exports = {
    displayUserComment,
    createUserProfile,
    welcomeMessage,
    updateNotification,
    createLink,
    calculateExpression,
    delayedAction,
    addListItem,
    safeDisplayComment,
    addButton
};