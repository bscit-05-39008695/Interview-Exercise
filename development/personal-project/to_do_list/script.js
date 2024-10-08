const taskInput = document.getElementById('taskInput');
const dateInput = document.getElementById('dateInput');
const durationInput = document.getElementById('durationInput');
const addButton = document.getElementById('addTask');
const taskList = document.getElementById('taskList');

function addTask() {
    const task = taskInput.value.trim();
    const date = dateInput.value; // Get date value
    const duration = durationInput.value; // Get duration value

    if (task && date && duration) { // Check if all fields are filled
        createTaskElement(task, date, duration);
        taskInput.value = '';
        dateInput.value = '';
        durationInput.value = '';
        saveTask();
    } else {
        alert('Please enter a task, date, and duration!');
    }
}

addButton.addEventListener('click', addTask);

function createTaskElement(task, date, duration) {
    const listItem = document.createElement('li');
    
    // Create a task description
    const taskDescription = document.createElement('span');
    taskDescription.textContent = `${task} (Due: ${date}, Duration: ${duration})`;
    listItem.appendChild(taskDescription);

    // Create the Delete button
    const deleteButton = document.createElement('button');
    deleteButton.textContent = 'Delete';
    deleteButton.className = 'deleteTask';
    listItem.appendChild(deleteButton);

    // Create the Edit button
    const editButton = document.createElement('button');
    editButton.textContent = 'Edit';
    editButton.className = 'editTask';
    listItem.appendChild(editButton);

    taskList.appendChild(listItem);

    // Delete button functionality
    deleteButton.addEventListener('click', function() {
        taskList.removeChild(listItem);
        saveTask();
    });

    // Edit button functionality
    editButton.addEventListener('click', function() {
        taskInput.value = task; // Set the input value to the current task
        dateInput.value = date; // Set the date input
        durationInput.value = duration; // Set the duration input
        taskList.removeChild(listItem);
        saveTask(); // Save the updated tasks
    });
}

function saveTask() {
    let tasks = [];
    taskList.querySelectorAll('li').forEach(function(item) {
        const text = item.querySelector('span').textContent;
        tasks.push(text.replace('Delete', '').replace('Edit', '').trim());
    });

    localStorage.setItem('tasks', JSON.stringify(tasks));
}

function loadTask() {
    const tasks = JSON.parse(localStorage.getItem('tasks')) || [];
    tasks.forEach(taskString => {
        if (taskString) { // Ensure taskString is not empty
            const [task, dueInfo] = taskString.split(' (Due: ');
            if (dueInfo) { // Ensure dueInfo is defined
                const [date, duration] = dueInfo.split(', Duration: ');
                createTaskElement(task, date.replace(')', ''), duration.replace(')', ''));
            }
        }
    });
}

// Load tasks on page load
loadTask();
