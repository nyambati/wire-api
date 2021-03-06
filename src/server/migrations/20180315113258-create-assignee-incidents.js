
module.exports = {
  up: (queryInterface, Sequelize) => {
    return queryInterface.createTable('assigneeIncidents', {
      userId: {
        type: Sequelize.STRING,
        onDelete: 'CASCADE',
        onUpdate: 'CASCADE',
        references: {
          model: 'Users',
          key: 'id',
          as: 'userId'
        }
      },
      incidentId: {
        type: Sequelize.STRING,
        onDelete: 'CASCADE',
        onUpdate: 'CASCADE',
        references: {
          model: 'Incidents',
          key: 'id',
          as: 'incidentId'
        }
      },
      assignedRole: {
        type:   Sequelize.ENUM,
        values: ['ccd', 'assignee', 'other']
      },
      createdAt: {
        allowNull: false,
        type: Sequelize.DATE
      },
      updatedAt: {
        allowNull: false,
        type: Sequelize.DATE
      }
    });
  },
  down: (queryInterface, Sequelize) => {
    return queryInterface.dropTable('assigneeIncidents');
  }
};
